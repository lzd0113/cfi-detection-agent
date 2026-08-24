# 攻击向量与防护机制

## 前向 CFI（Forward-Edge）防护的攻击

### 1. vtable hijacking（虚表劫持）
- **攻击原理**：攻击者通过内存漏洞（如 UAF、buffer overflow）篡改对象的 vptr，使其指向伪造的虚表，从而调用攻击者控制的函数。
- **防护机制**：LLVM CFI cfi-vcall，在虚函数调用前检查 vptr 指向的虚表类型哈希。
- **检测指标**：vcall 调用点的 CFI 覆盖率。覆盖率低 = 大量虚函数调用无保护 = vtable hijacking 风险高。
- **高风险场景**：面向对象密集的模块（如 arkui、graphic），虚函数调用频繁。

### 2. 间接调用劫持（icall hijacking）
- **攻击原理**：覆盖函数指针变量，使间接调用（BLR）跳转到攻击者地址（如 system()、execve()）。
- **防护机制**：LLVM CFI cfi-icall，检查函数指针的类型签名。
- **检测指标**：icall 调用点的 CFI 覆盖率。
- **高风险场景**：大量使用回调函数的模块（如 communication、multimedia）。

### 3. 类型混淆（Type Confusion）
- **攻击原理**：将基类指针强制转换为不相关的派生类，访问不存在的成员，导致越界读写。
- **防护机制**：cfi-derived-cast、cfi-unrelated-cast。
- **检测指标**：无法直接检测，但 CFI 开启即覆盖此防护。

## 后向 CFI（Backward-Edge）防护的攻击

### 4. ROP（Return-Oriented Programming）
- **攻击原理**：通过覆盖栈上的返回地址，拼接多个 gadget（以 RET 结尾的代码片段），实现任意操作。
- **防护机制**：ARM PAC（Pointer Authentication），在函数入口签名返回地址，函数返回时验证。
- **检测指标**：PAC 函数覆盖率。覆盖率低 = 大量函数返回地址未签名 = ROP 风险高。
- **关键指令**：
  - 签名：PACIASP, PACIBSP（函数入口）
  - 认证：AUTIASP, AUTIBSP, RETAA, RETAB（函数返回）
- **PAC 分类**：
  - protected（有签名+有认证）→ 有效防护 ROP
  - sign_only（有签名无认证）→ 签名无效，等于无保护
  - no_pac（无签名无认证）→ 无保护

### 5. JOP（Jump-Oriented Programming）
- **攻击原理**：类似 ROP，但使用间接跳转（BR/BLR）而非返回（RET）拼接 gadget。
- **防护机制**：ARM BTI（Branch Target Identification），要求间接跳转目标必须有 BTI 指令。
- **检测指标**：BTI 函数覆盖率。覆盖率低 = 大量函数入口无 BTI = JOP 风险高。
- **关键指令**：BTI, BTI c, BTI j, BTI jc（函数入口）

## 前向 + 后向协同

| 防护 | 方向 | 防护的攻击 | 架构 |
|------|------|-----------|------|
| LLVM CFI | 前向 | vtable hijacking, type confusion, icall | 32位 + 64位 |
| BTI | 前向 | JOP | 仅 AArch64 |
| PAC | 后向 | ROP | 仅 AArch64 |

三者互补：
- CFI 防护间接调用（前向）
- BTI 防护间接跳转目标（前向）
- PAC 防护返回地址（后向）
- 完整防护需要三者同时开启
