# LLVM CFI 控制流完整性原理

## 概述

Clang/LLVM 提供多种 CFI（Control Flow Integrity）scheme，通过在编译时插入运行时检查，防止攻击者劫持程序控制流。通过 `-fsanitize=cfi` 启用，需要配合 LTO（`-flto` 或 `-flto=thin`）。

## 7 种 CFI Scheme

| Scheme | 标志 | 防护目标 |
|--------|------|---------|
| 虚函数调用检查 | `-fsanitize=cfi-vcall` | 虚函数调用时 vptr 类型不匹配 |
| 非虚成员调用检查 | `-fsanitize=cfi-nvcall` | 非虚函数调用时对象类型不匹配 |
| 派生类转换检查 | `-fsanitize=cfi-derived-cast` | base→derived 类型转换错误 |
| 无关类型转换检查 | `-fsanitize=cfi-unrelated-cast` | void*→目标类型转换错误 |
| 间接函数调用检查 | `-fsanitize=cfi-icall` | 函数指针调用时函数类型不匹配 |
| 成员函数指针检查 | `-fsanitize=cfi-mfcall` | 成员函数指针调用时类型不匹配 |
| 内核间接调用 | `-fsanitize=kcfi` | 内核态函数指针检查（无需 LTO） |

## 工作机制

### 虚函数调用检查 (cfi-vcall)
1. 编译器为每个含虚函数的类生成类型哈希
2. 在虚函数调用前插入 `__cfi_slowpath` 检查
3. 检查 vptr 指向的 vtable 的类型哈希与静态类型是否匹配
4. 不匹配则 abort

### 间接函数调用检查 (cfi-icall)
1. 编译器为每个函数生成类型签名
2. 间接调用时检查函数地址的类型签名
3. 通过跳转表（jump table）实现，替换导出函数地址

### 检测方法
- **.so 级**：检查 `__cfi_check` 符号是否定义（st_value != 0）
- **函数级**：`.cfi` 后缀函数为受保护入口，`__cfi*` 为基础设施
- **调用点级**：扫描 BLR 指令，检查附近是否有 `__cfi_slowpath` 调用

## cross-DSO 支持

`-fsanitize-cfi-cross-dso` 允许 CFI 检查跨共享库边界生效。OpenHarmony 使用此模式保护跨 .so 的间接调用。

## blocklist 豁免

通过 Sanitizer Special Case List 可豁免特定函数/文件/类型的 CFI 检查：
```
# 豁免特定函数
fun:*PerformanceCritical*
# 豁免特定类型
type:std::*
```

## 性能影响

- 虚函数调用检查：性能开销 <1%（Chromium Dromaeo 基准测试）
- 二进制大小增长：最多 15%
- 间接调用检查：有跳转表开销，但对大多数应用影响小

## 安全意义

CFI 防护的攻击向量：
- **vtable hijacking**：篡改虚表指针，调用非预期函数
- **type confusion**：类型转换后访问不匹配的对象
- **间接调用劫持**：覆盖函数指针，调用任意函数

CFI 不防护：
- 直接调用（BL 指令）不受影响
- 不含虚函数的类不受 vcall 保护
- 未编译 CFI 的 .so 内部调用不受保护
