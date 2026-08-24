BTI 检测结果分析：为什么绝大部分 .so 只检测到 4 个 BTI 函数
================================================================

一、检测结果概述
----------------

对 OpenHarmony 6.1 AArch64 全量编译产物（2953 个 .so）进行 BTI 检测，结果：

  - 2911 个 .so 有 BTI 指令（98.6%）
  - 42 个 .so 无任何 BTI 指令（1.4%）
  - 每个 .so 平均约 4 条 BTI 指令
  - 全部为 BTI c（间接调用目标），无 BTI j / BTI jc
  - 无任何 .so 声明 .note.gnu.property BTI 属性标记


二、4 个 BTI 函数分别是什么
----------------------------

以 libaudio_clock.z.so 为例，4 个 BTI c 指令位于以下函数入口：

  1. _init       (地址 0x7abc, 段 .init)
     - 动态链接器加载 .so 时通过函数指针调用
     - 负责 C++ 全局构造函数初始化
     - BTI c 保护：防止攻击者篡改 _init 函数指针劫持控制流

  2. _fini       (地址 0x7ad0, 段 .fini)
     - 动态链接器卸载 .so 时通过函数指针调用
     - 负责 C++ 全局析构函数清理
     - BTI c 保护：防止篡改 _fini 函数指针

  3. __do_init   (地址 0x8000, 段 .text)
     - 遍历 .init_array 数组，逐个调用每个构造函数
     - 是 _init 的内部实现，负责执行全部全局构造
     - BTI c 保护：作为间接调用目标，防止跳转到函数中间

  4. __do_fini   (地址 0x8074, 段 .text)
     - 遍历 .fini_array 数组，逐个调用每个析构函数
     - 是 _fini 的内部实现，负责执行全部全局析构
     - BTI c 保护：同上

这 4 个函数都是编译器/链接器自动生成的运行时基础设施代码，不是应用
业务代码。每个 .so 都会有这 4 个函数，与应用逻辑无关。


三、为什么只能检测到 4 个
-------------------------

根据《OpenHarmony 6.1 源码 BTI 配置分析报告》的源码分析：

3.1 BTI 启用机制（三层）

  第一层：全局能力开关（security_config.gni）
    - support_branch_protector_bti = true
    - 条件：target_cpu == "arm64" && is_ohos && is_standard_system
    - 含义：工具链"具备" BTI 能力，但不自动给所有目标加 BTI 标志

  第二层：编译模板注入（cxx.gni，4 处对称逻辑）
    - 需要目标 BUILD.gn 显式传入 branch_protector_frt = "bti"
    - 才会注入 cflags += "-mbranch-protection=bti"
    - 和 ldflags += "-Wl,-z,force-bti"
    - ⚠ 源码检索结果：仓库内无任何组件 BUILD.gn 设置该参数
    - → 业务代码层面 BTI 实际未启用

  第三层：musl libc 强制启用（musl_template.gni）
    - cflags += "-mbranch-protection=bti"
    - cflags += "-mmark-bti-property"
    - asmflags = cflags（汇编代码也加）
    - ✅ 仓库内唯一真正应用 BTI 编译标志的位置

3.2 为什么是 4 个

  因为 BTI 编译标志只应用在 musl libc 上，而 _init / _fini / __do_init /
  __do_fini 这 4 个函数是链接器从 musl libc 的 crt 启动文件
 （crtbegin.o / crtend.o）中引入的，它们受 musl 的 BTI 编译标志保护。

  应用业务代码的编译没有加 -mbranch-protection=bti（因为没有组件设置
  branch_protector_frt = "bti"），所以业务函数入口没有 BTI 指令。

  总结：
    musl libc 加了 BTI → 链接器引入的 4 个 crt 函数有 BTI → 每个 .so 检测到 4 个
    业务代码没加 BTI → 应用函数入口无 BTI → 函数覆盖率极低（如 4/158 = 2.5%）

3.3 链接器行为

  即使业务代码没有加 BTI 标志，链接器在生成 .so 时仍然会：
  1. 从 musl crt 文件中引入 _init / _fini / __do_init / __do_fini
  2. 这些函数已经带了 BTI c 指令（因为 musl 编译时加了 BTI）
  3. 链接器不会给业务代码的函数自动添加 BTI（没有 -mbranch-protection=bti）
  4. 也不会自动标记 .note.gnu.property BTI 属性（没有 -mmark-bti-property）

  所以每个 .so 都有恰好 4 个 BTI（来自 crt 文件），不多不少。


四、为什么无 .note.gnu.property 属性标记
----------------------------------------

.note.gnu.property 中的 BTI 标记（GNU_PROPERTY_AARCH64_FEATURE_1_BTI）
需要编译时加 -mmark-bti-property 才会生成。

只有 musl libc 加了这个标志，但 musl 的目标文件被链接进各业务 .so 后，
.note.gnu.property 属性不会自动传播到最终 .so 上。

最终 .so 的链接没有加 -mmark-bti-property，所以 .note.gnu.property
中不包含 BTI 标记 → 检测到 0/2953 个 .so 有 BTI 属性标记。


五、为什么只有 BTI c，没有 BTI j / BTI jc
------------------------------------------

BTI 指令有 4 种变体：

  BTI c  (HINT #38) — 合法的间接调用（BLR）目标
  BTI j  (HINT #36) — 合法的间接跳转（BR）目标
  BTI jc (HINT #34) — 合法的间接调用或跳转目标
  BTI    (HINT #32) — 合法的任意间接分支目标

4 个 crt 函数入口放的都是 BTI c，因为：
  - 动态链接器通过 BLR（间接调用）跳转到 _init / _fini
  - BLR 的合法目标是 BTI c 或 BTI jc 或 BTI
  - 编译器选择 BTI c（最精确的标记，只允许间接调用）

业务代码如果启用 BTI，函数入口会根据调用方式选择不同的 BTI 变体：
  - 虚函数调用目标 → BTI c
  - 间接跳转目标 → BTI j
  - 两者都是 → BTI jc
  - 不确定 → BTI

但业务代码没启用 BTI，所以只有 crt 文件的 4 个 BTI c。


六、检测的 4 个 BTI 是否合理
-----------------------------

合理。这 4 个 BTI 指令保护的是 .so 加载/卸载流程中的关键间接调用：

  动态链接器持有 _init 和 _fini 的函数指针：
    dlopen()  → BLR [_init]    → BTI c 校验通过 → __do_init → 各构造函数
    dlclose() → BLR [_fini]    → BTI c 校验通过 → __do_fini → 各析构函数

  如果攻击者篡改了 _init/_fini 的函数指针：
    - 无 BTI：CPU 直接跳转到攻击者地址，控制流被劫持
    - 有 BTI：CPU 检查目标首指令不是 BTI c → 抛 SIGILL 异常 → 攻击失败

  __do_init / __do_fini 的 BTI 是额外保护：
    - 即使 _init 被调用，__do_init 也可能被间接调用（某些路径）
    - BTI c 确保这些函数也不能被任意跳转

所以这 4 个 BTI 是"基线保护"——保护 .so 生命周期中最关键的间接调用入口，
但不保护业务代码的函数。要保护业务代码，需要在 BUILD.gn 中显式设置
branch_protector_frt = "bti"。


七、结论
--------

1. 每个 .so 检测到 4 个 BTI c 是正常的——它们来自 musl libc 的 crt
   启动文件（_init / _fini / __do_init / __do_fini），是链接器自动引入的

2. 业务代码没有 BTI 是因为 OpenHarmony 6.1 的业务组件 BUILD.gn 没有设置
   branch_protector_frt = "bti"，BTI 编译标志只应用在 musl libc 上

3. 要提高 BTI 覆盖率，需要在业务组件的 BUILD.gn 中显式启用 BTI：
     branch_protector_frt = "bti"
   或在构建模板中默认开启（需评估兼容性）

4. 检测结果是准确的——98.6% 的 .so 有 4 个 BTI（crt 函数），1.4% 的
   .so 无 BTI（可能是纯数据库或特殊链接方式），符合源码配置分析
