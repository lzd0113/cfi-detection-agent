# ARM 安全特性：PAC 与 BTI

## PAC（Pointer Authentication）

### 架构概述
ARMv8.3 引入的指针认证扩展，通过在指针中插入认证码（PAC）来检测指针是否被篡改。

### 工作原理
1. **签名**：用密钥（系统寄存器持有）+ 指针 + 上下文值（如 SP）计算 PAC，插入指针高位
2. **认证**：验证时重新计算 PAC，与指针中的 PAC 比较，不匹配则产生异常
3. **密钥**：5 个独立密钥（APIAKey、APIBKey、APDAKey、APDBKey、APGAKey）

### HINT 空间指令
PAC 指令分配在 HINT 编码空间，在无 PAC 支持的 CPU 上表现为 NOP：
- **签名指令**：PACIASP (imm7=25), PACIBSP (imm7=27), PACIA/IBSP 等
- **认证指令**：AUTIASP (imm7=29), AUTIBSP (imm7=31), AUTIA/IBSP 等
- **返回指令**：RETAA (PAC+RET), RETAB (PAC+RET)

### 函数级分类
| 分类 | 条件 | 安全状态 |
|------|------|---------|
| protected | 有签名 + 有认证 | 有效防护 ROP |
| sign_only | 有签名无认证 | 签名无效，等于无保护 |
| no_pac | 无签名无认证 | 无 ROP 防护 |

### .note.gnu.property
ELF 文件声明 PAC 支持：
- `FEATURE_1_PAC` flag = 编译时启用 PAC（`-mbranch-protection=pac-ret`）
- 内核据此决定是否分配 PAC 密钥

### 安全意义
- 防 ROP：攻击者无法伪造有效的返回地址（不知道密钥）
- 防 ret2libc：返回地址被篡改后认证失败，触发异常
- 性能开销：每函数入口/出口 2 条指令，开销极小

## BTI（Branch Target Identification）

### 架构概述
ARMv8.5 引入的分支目标标识，要求间接跳转目标必须有 BTI 指令。

### 工作原理
1. 内核根据 `.note.gnu.property` 的 `FEATURE_1_BTI` flag 决定是否启用 BTI 强制
2. 启用后，间接跳转（BR/BLR）到非 BTI 指令地址会触发异常
3. 编译器在函数入口插入 BTI 指令

### BTI 指令类型
| 指令 | imm7 | 含义 |
|------|------|------|
| BTI | 32 | 允许 BR/BLR 跳转 |
| BTI c | 34 | 仅允许 BLR（call）跳转 |
| BTI j | 36 | 仅允许 BR（jump）跳转 |
| BTI jc | 38 | 允许 BR 或 BLR 跳转 |

### 函数级检测
- **有 BTI**：函数入口首指令为 BTI 指令
- **无 BTI**：函数入口无 BTI，间接跳转到此函数会触发异常

### .note.gnu.property
ELF 文件声明 BTI 支持：
- `FEATURE_1_BTI` flag = 编译时启用 BTI（`-mbranch-protection=standard`）

### 安全意义
- 防 JOP：攻击者无法跳转到函数中间的 gadget
- 与 PAC 互补：BTI 防前向（跳转），PAC 防后向（返回）
- 32 位 ARM 不支持 BTI（ARMv8.5-A 专属）

## PAC + BTI 协同

| 攻击 | PAC 防护 | BTI 防护 |
|------|---------|---------|
| ROP（利用返回地址） | ✓ 签名返回地址 | - |
| JOP（利用间接跳转） | - | ✓ 验证跳转目标 |
| ret2libc | ✓ | - |
| 间接调用劫持 | - | ✓ |

编译选项：`-mbranch-protection=standard` 同时启用 PAC + BTI。
