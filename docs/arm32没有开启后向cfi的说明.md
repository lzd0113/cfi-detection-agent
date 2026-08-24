===============================================================================
    rk3568 用户态 (ARM32) 未开启后向 CFI 的分析说明
===============================================================================

分析对象: libaccount_common.z.so (account 模块, 有前向 CFI)
分析目录: E:\test\lib.unstripped\account\os_account\
分析工具: nm, readelf, PowerShell 字节级读取
生成时间: 2026-07-15

===============================================================================
一、背景
===============================================================================

CFI (Control Flow Integrity, 控制流完整性) 分为两个方向:

  前向 CFI (Forward-edge CFI):
    - 保护间接调用 (函数指针、虚函数调用)
    - 防止攻击者篡改函数指针，将间接调用重定向到非法目标
    - LLVM 实现: -fsanitize=cfi
    - 二进制体现: __cfi_check 函数、.cfi 后缀插桩函数、CFI 跳转表、trap 填充区

  后向 CFI (Backward-edge CFI):
    - 保护返回地址
    - 防止攻击者篡改栈上的返回地址 (ROP 攻击)
    - 实现方式:
      (1) PAC (Pointer Authentication Code) — ARM64 硬件特性 (ARMv8.3-A)
          - 函数入口: PACIASP (对返回地址签名)
          - 函数返回: AUTIASP (验证返回地址签名)
      (2) Shadow Call Stack (SCS) — 软件实现
          - 使用独立寄存器 (ARM64 的 x18) 存储影子栈指针
          - 返回地址存入影子栈，与主栈隔离
          - LLVM 实现: -fsanitize=shadow-call-stack

===============================================================================
二、分析对象信息
===============================================================================

  文件: libaccount_common.z.so
  大小: 419 KB (未 strip 版本)
  架构: ELF32, Machine: ARM (ARMv7, 32 位 Thumb-2)
  编译器: OHOS (dev) clang version 15.0.4
  前向 CFI: 已开启 (sanitize.cfi = true, cfi_cross_dso = true)

  ARM Attributes:
    Tag_CPU_arch: v7
    Tag_CPU_arch_profile: Application
    Tag_ARM_ISA_use: Yes
    Tag_THUMB_ISA_use: Thumb-2

===============================================================================
三、前向 CFI 在反汇编中的体现 (已开启)
===============================================================================

前向 CFI 在此 .so 中有 4 处明显体现:

3.1 __cfi_check 函数 (地址 0x7001)
------------------------------------------------------------------------
  这是跨 DSO CFI 的核心入口函数。当 cfi_cross_dso = true 时，编译器
  在本 .so 中导出 __cfi_check，外部 .so 在对本模块内的函数指针发起
  间接调用前，会先调用本模块的 __cfi_check 来校验该指针是否合法。

  nm 输出:
    00007001 T __cfi_check          ← 已定义, 全局导出

  机器码 (Thumb-2, 小端序):
    0x7001: B5 4B F2 8B    push {r4, lr} + movw (加载类型哈希)
    0x7005: 6E 48 F2 75    movw (加载类型哈希)
    0x7009: 6C C9 F2 15    movt (加载类型哈希)
    0x700D: 6E C1 F6 E3    movt (加载类型哈希)
    0x7011: 4C BE EB 00    subs.w (比较类型哈希)
    0x7015: 0E 7C EB 01    sbcs.w (比较类型哈希, 进位)
    0x7019: 0E 49 DB 43    bge (匹配→通过, 不匹配→失败)

  分析: movw/movt 指令加载 64 位类型哈希到寄存器, subs/sbcs 进行
  比较, bge 决定是否通过检查。这是前向 CFI 的核心验证逻辑。

3.2 .cfi 后缀函数 (17 个)
------------------------------------------------------------------------
  编译器为每个需要跨 DSO 校验的导出函数生成 .cfi 插桩版本 (跳板)。
  外部调用走 .cfi 版本而非原始函数，确保经过 CFI 检查。

  nm 输出 (共 17 个):
    0000789d t _ZN4OHOS18ConvertToJSErrCodeEi.cfi
    00007801 t _ZN4OHOS27OsAccountConvertToJSErrCodeEi.cfi
    000076f1 t _ZN4OHOS28AppAccountConvertToJSErrCodeEi.cfi
    0000765d t _ZN4OHOS31AppAccountConvertOtherJSErrCodeEi.cfi
    0000e9b9 t _ZN4OHOS9AccountSA17AccountLogWrapper10JudgeLevelE...Ei.cfi
    ... (共 17 个)

3.3 .L.cfi.jumptable 跳转表 (12 个条目, 地址 0xf1a9)
------------------------------------------------------------------------
  存储合法间接调用目标的地址表, __cfi_check 在验证时查此表。

  nm 输出:
    0000f1a9 t .L.cfi.jumptable
    0000f1ad t .L.cfi.jumptable.37
    0000f1a9 t .L.cfi.jumptable.38
    ... (共 12 个条目)

3.4 CFI 影子区 / trap 填充 (地址 0x6144)
------------------------------------------------------------------------
  未登记为合法间接调用目标的地址区域填充 0xd4d4d4d4。
  0xd4d4 是 ARM Thumb 的 trap 指令编码。控制流被劫持跳到这些
  未登记地址时，立即触发 trap，阻止攻击。

  机器码:
    0x6144: D4 D4 D4 D4    .word 0xd4d4d4d4    ← trap
    0x6148: D4 D4 D4 D4    .word 0xd4d4d4d4    ← trap
    0x614C: D4 D4 D4 D4    .word 0xd4d4d4d4    ← trap

===============================================================================
四、后向 CFI 检测结果 (未开启)
===============================================================================

4.1 PAC (指针认证) — 不存在
------------------------------------------------------------------------
  检测方式: nm 搜索 paciasp/autiasp/pacisp/autisp 符号
  结果: 无任何 PAC 相关符号

  原因: PAC (Pointer Authentication Code) 是 ARM64 (AArch64,
  ARMv8.3-A) 的硬件特性。此 .so 为 ARM32 (ARMv7, Thumb-2),
  不支持 PAC 指令集 (PACIASP/AUTIASP 等)。

  ARM Attributes 确认:
    Tag_CPU_arch: v7    ← ARMv7, 不是 ARMv8-A

4.2 Shadow Call Stack (SCS) — 不存在
------------------------------------------------------------------------
  检测方式: nm 搜索 scs/shadow_stack/shadow 相关符号
  结果: 无任何 SCS 相关符号

  原因: 源码中的 Shadow Call Stack 构建配置有架构守卫:

  文件: build/config/sanitizers/BUILD.gn 第 645-654 行:
    config("shadow_call_stack_config") {
      if (target_cpu == "arm64") {         ← 只在 64 位下生效
        cflags = [ "-fsanitize=shadow-call-stack" ]
        ldflags = cflags
        configs = [ ":sanitizer_trap_all_flags" ]
      }
    }

  文件: build/config/sanitizers/sanitizers.gni 第 308-310 行:
    _scs = defined(sanitize.scs) && sanitize.scs
    if (_scs) {
      configs += [ "//build/config/sanitizers:shadow_call_stack_config" ]
    }

  由于 target_cpu = "arm" (32 位), shadow_call_stack_config 中的
  if (target_cpu == "arm64") 条件不满足, SCS 配置不生效。

4.3 全源码搜索 — 无组件启用 SCS
------------------------------------------------------------------------
  在整个 OpenHarmony 源码树中搜索所有 BUILD.gn 文件,
  查找 sanitize.scs = true 或 scs = true:
  结果: 无任何组件声明启用 Shadow Call Stack

4.4 普通函数入口指令 (无后向 CFI 保护)
------------------------------------------------------------------------
  以 __cfi_check_fail 函数 (0x6131) 为例:

  机器码:
    0x6130: 80 B5    push {r7, lr}     ← 标准函数序言
                                      lr (返回地址) 直接入栈, 无签名保护
    0x6134: 18 B1    cbz r0, #0x6144
    0x6138: 28 BF    it hs
    0x613C: 80 BD    pophs {r7, pc}    ← 标准函数返回
                                      pc 从栈恢复, 可被篡改 (ROP 风险)

  对比: 如果有 PAC 保护 (ARM64), 函数入口应为:
    PACIASP              ← 对 lr (返回地址) 签名
    push {r7, lr}
    ...
    AUTIASP              ← 验证 lr 签名, 不匹配则 trap
    pop {r7, pc}

  但 ARM32 不支持 PACIASP/AUTIASP 指令, 无法实现。

===============================================================================
五、根本原因分析
===============================================================================

5.1 架构配置
------------------------------------------------------------------------
  文件: vendor/hihope/rk3568/config.json 第 5 行:
    "target_cpu": "arm"     ← 32 位 ARM

  文件: device/board/hihope/rk3568/config.gni:
    board_arch = "armv8-a"  ← 芯片架构支持 64 位
    board_cpu  = "cortex-a55"  ← 64 位核

  结论: rk3568 芯片是 64 位的 (ARMv8-A, Cortex-A55), 但 OpenHarmony
  明确配置为 32 位编译 (target_cpu = "arm")。

5.2 后向 CFI 不可用的原因链
------------------------------------------------------------------------

  target_cpu = "arm" (32 位)
    │
    ├─→ PAC 不可用
    │     PAC 是 ARM64 (AArch64, ARMv8.3-A) 硬件特性
    │     ARM32 (ARMv7) 指令集不支持 PACIASP/AUTIASP
    │     编译器不会生成 PAC 指令
    │
    ├─→ Shadow Call Stack 不可用
    │     build/config/sanitizers/BUILD.gn 中:
    │     if (target_cpu == "arm64") { ... }
    │     target_cpu = "arm" 不满足条件, SCS 配置不生效
    │     即使有组件声明 sanitize.scs = true, 配置也不会应用
    │
    └─→ 结论: 32 位用户态只能使用前向 CFI (-fsanitize=cfi)
              后向 CFI 需要 64 位架构 (arm64)

5.3 对比: 如何启用后向 CFI
------------------------------------------------------------------------
  如果将 target_cpu 改为 "arm64" (像 dayu210 产品那样):

  vendor/hihope/dayu210/config.json:
    "target_cpu": "arm64"    ← 64 位

  则:
  (1) PAC 可用 — 编译器可生成 PACIASP/AUTIASP 指令
      需要 -mbranch-protection=standard 编译选项
  (2) Shadow Call Stack 可用 — shadow_call_stack_config 生效
      需要 sanitize.scs = true 在 BUILD.gn 中声明

===============================================================================
六、总结
===============================================================================

  | 检测项                  | 结果 | 原因
  |-------------------------|------|------------------------------------------
  | 前向 CFI (__cfi_check)  | ✅ 有 | -fsanitize=cfi 在 ARM32 上正常工作
  | 前向 CFI (.cfi 函数)    | ✅ 有 | 17 个 .cfi 后缀插桩函数
  | 前向 CFI (跳转表)       | ✅ 有 | 12 个 .L.cfi.jumptable 条目
  | 前向 CFI (trap 填充)    | ✅ 有 | 0xd4d4d4d4 影子区
  | 后向 CFI (PAC)          | ❌ 无 | ARM32 不支持 PAC 指令 (需 ARM64)
  | 后向 CFI (Shadow Stack) | ❌ 无 | 配置仅对 arm64 生效, 且无组件启用
  | 函数返回地址保护         | ❌ 无 | 标准 push/pop {lr/pc}, 无签名验证

  结论:
    rk3568 用户态编译为 32 位 ARM (ARMv7), 导致后向 CFI 完全不可用。
    PAC 需要 ARM64 硬件支持, Shadow Call Stack 的构建配置有 arm64 守卫。
    当前只有前向 CFI 可用, 返回地址无保护, 存在 ROP 攻击风险。

  建议:
    1. 如需后向 CFI, 可将 target_cpu 改为 "arm64"
    2. 或在 ARM32 上实现软件版返回地址保护 (当前 OpenHarmony 未实现)
    3. 前向 CFI 已覆盖间接调用保护, 可缓解部分攻击

===============================================================================
报告结束
===============================================================================
