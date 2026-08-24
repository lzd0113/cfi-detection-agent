# OpenHarmony 模块风险画像

## 安全敏感模块（高优先级，无 CFI = 高风险）

| 模块 | 说明 | 关键 .so | 无 CFI 风险 |
|------|------|---------|------------|
| security | 安全子系统 | libhuks_engine（密钥管理）, libcrypto（加解密） | 密钥泄露、加密绕过 |
| account | 账户管理 | libaccountmanager, libaccount_iam | 账户劫持、认证绕过 |
| tee | 可信执行环境 | libtee_client, libcadaemon | TEE 穿透、敏感数据泄露 |
| useriam | 用户身份认证 | libuserauth（指纹/人脸） | 生物特征数据泄露 |

## 核心框架模块（中优先级）

| 模块 | 说明 | 关键 .so | 无 CFI 风险 |
|------|------|---------|------------|
| arkui | 方舟UI引擎 | libace（2.7GB）, libace_compatible | UI 劫持、信息泄露 |
| arkcompiler | 方舟编译器 | libark_jsruntime, libark_jsoptimizer | 代码注入、沙箱逃逸 |
| communication | 通信 | libbluetooth, libwifi | 中间人攻击、数据篡改 |
| multimedia | 多媒体 | libmedia, libavsession | 媒体解析漏洞利用 |
| distributeddatamgr | 分布式数据 | libdistributeddb, libkv_store | 数据泄露、数据篡改 |
| bundlemanager | 包管理 | libbms, libbundle_framework | 包篡改、权限提升 |

## 基础设施模块（中优先级）

| 模块 | 说明 | 关键 .so | 无 CFI 风险 |
|------|------|---------|------------|
| graphic | 图形 | librender_service, libskia | GPU 利用、显示劫持 |
| hdf | 驱动框架 | 各驱动 .so | 驱动漏洞利用 |
| startup | 系统启动 | libinit, libparam | 启动劫持、参数篡改 |
| powermgr | 电源管理 | libpower, libbattery | DoS、电源状态篡改 |
| notification | 通知 | libans, libnotification | 通知伪造、信息泄露 |
| inputmethod | 输入法 | libinputmethod | 键盘记录、输入劫持 |

## 低风险模块

| 模块 | 说明 | 无 CFI 原因 |
|------|------|------------|
| thirdparty | 第三方库 | 预编译，无法修改源码 |
| xts | 兼容性测试 | 非生产代码 |
| testfwk | 测试框架 | 非生产代码 |
| build | 构建系统 | 无敏感数据 |

## 厂商预编译库（不可修改）

| 文件 | 功能 | 风险评估 |
|------|------|---------|
| libmali-bifrost-g52-g2p0-ohos.so | Mali GPU 驱动 | 低（驱动层，内核隔离） |
| librga.z.so | RGA 2D 图形 | 低（硬件加速，功能受限） |
| librockchip_mpp.z.so | 媒体处理 | 低（编解码，无敏感数据） |
| librkaiq.z.so | ISP 图像处理 | 低（图像处理，无敏感数据） |

## 评估流程

1. 查看检测结果的 `query_modules` 输出
2. 按"安全敏感 → 核心框架 → 基础设施 → 低风险"排序
3. 对每个模块：
   - CFI 覆盖率 < 50% → 标记风险
   - 安全敏感模块 CFI = 0% → 高风险
   - 函数数 > 10000 且无 CFI → 高风险（攻击面大）
4. 对 AArch64 .so：
   - PAC 覆盖率 < 30% → ROP 风险
   - BTI 覆盖率 < 10% → JOP 风险
5. 对 vcall/icall：
   - 调用点 > 100 且 CFI 覆盖率 < 30% → 中风险
