# 安卓 CFI + PAC + BTI 部署经验

## Android CFI 部署历程

### Android 8 (Oreo, 2017)
- 在 media framework 中首次引入 LLVM CFI
- 使用 `-fsanitize=cfi -flto=thin`
- 启用 cross-DSO CFI（`-fsanitize-cfi-cross-dso`）

### Android 9 (Pie, 2018)
- 扩展 CFI 到更多框架组件
- 使用 blocklist 对特定函数豁免

### Android 10 (2019)
- CFI 覆盖整个平台代码
- 引入 PAC 支持用于 ARMv8.3+ 设备

### Android 11 (2020)
- 扩展 PAC 支持范围
- 增强 cross-DSO CFI 覆盖

### Android 12 (2021)
- 引入 BTI 支持用于 ARMv8.5+ 设备
- PAC + BTI 协同部署

## 关键经验

### 1. 分阶段推进
Android 的经验表明 CFI 不应一次全量启用：
- 先在小范围（media framework）试点
- 验证正确性和性能影响
- 逐步扩展到全平台
- OpenHarmony 可参考同样的推进策略

### 2. blocklist 是必要的
- 某些函数因性能或兼容性问题需要豁免
- 典型豁免场景：热路径函数、汇编函数、跨语言接口
- blocklist 应有审查流程，避免滥用

### 3. cross-DSO 是关键
- Android 使用 cross-DSO CFI 保护跨 .so 的间接调用
- 这是 OpenHarmony 同样需要的（大量跨组件调用）
- cross-DSO 有额外性能开销，需权衡

### 4. PAC 渐进部署
- 先在关键进程（Zygote、system_server）部署
- 逐步扩展到普通应用
- sign_only 比例应逐步降低到 0

### 5. BTI 与 PAC 配合
- BTI 防前向（JOP），PAC 防后向（ROP），缺一不可
- 编译选项 `-mbranch-protection=standard` 同时启用
- 32 位架构不支持（ARMv8.5-A 专属）

## 对 OpenHarmony 的建议

### 优先级排序
1. **安全敏感模块优先**：security、account、tee、useriam 先开 CFI
2. **核心框架其次**：arkui、communication、multimedia
3. **基础库再次**：commonlibrary、distributeddatamgr
4. **第三方库**：预编译，无法修改，关注是否有更新版本

### 性能考虑
- CFI 性能开销 <1%（虚函数检查）
- PAC 每函数 2 条指令，开销极小
- BTI 每函数 1 条指令，开销极小
- 真正的开销在 LTO 编译时间和二进制大小（最多+15%）

### 风险接受标准
| 场景 | 是否可接受 | 原因 |
|------|-----------|------|
| thirdparty 无 CFI | 可接受 | 预编译，无法修改 |
| 厂商驱动库无 CFI | 可接受 | 闭源，无法修改 |
| security 模块无 CFI | 不可接受 | 处理敏感数据 |
| 核心框架无 CFI | 需评估 | 攻击面大 |
| PAC sign_only >50% | 需关注 | 签名未验证 |
