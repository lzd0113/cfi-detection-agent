# 函数总数统计口径分析报告

## 一、问题背景

在 OpenHarmony CFI 检测系统中，同一个 .so 文件在不同位置显示的函数总数不一致。例如 `libadsservice_extension.z.so`：

| 位置 | 显示数量 | 去重方式 |
|------|---------|---------|
| Excel "函数总数" | 84 | 原始符号名（mangled） |
| 弹窗标题（修复前） | 84 | 原始符号名（mangled） |
| 弹窗函数列表 | 78 | demangled 名 |
| 弹窗标题（修复后） | 78 | demangled 名（与列表一致） |

差异为 6，原因是 6 对不同的 mangled 符号名 demangle 后指向了同一个 demangled 名字。


## 二、两种去重方式

### 方式一：按原始符号名（mangled name）去重

统计对象：`.symtab` 中 `STT_FUNC` 类型的符号，每个符号的 `name` 字段（mangled name）。

```
.symtab 中的符号：
  _ZN4OHOS10ParcelableD1Ev   ← mangled name
  _ZN4OHOS10ParcelableD0Ev   ← mangled name（不同）
  
按 mangled 去重 → 计为 2 个函数
```

**实现代码**（`classify_functions()`）：
```python
other_funcs_set = set()              # set 按 mangled name 去重
for sym in symtab.iter_symbols():
    if sym['st_info']['type'] != 'STT_FUNC':
        continue
    if sym['st_value'] == 0:        # 跳过外部符号
        continue
    name = sym.name                  # mangled name
    if not name:
        continue
    other_funcs_set.add(name)       # 自动去重
```

**特点**：
- 每个符号名对应一个独立的函数入口和代码体
- 不同地址的同名函数（COMDAT 折叠）会被去重为 1 个
- D0/D1/D2 析构函数（mangled 名不同）被计为不同函数

### 方式二：按 demangled name 去重

统计对象：经过 c++filt demangle 后的函数名。

```
_ZN4OHOS10ParcelableD1Ev → demangle → OHOS::Parcelable::~Parcelable()
_ZN4OHOS10ParcelableD0Ev → demangle → OHOS::Parcelable::~Parcelable()
                                        ↑ 同一个 demangled 名

按 demangled 去重 → 计为 1 个函数
```

**实现代码**（`build_module_data()` + `generate_sqlite()`）：
```python
# demangle 后转为索引
r['truly_unprotected'] = [get_name_idx(n) for n in r['truly_unprotected']]
# get_name_idx() 内部：
#   dem = demangled_map.get(name, name)  # 先 demangle
#   if dem not in name_to_idx:           # 按 demangled 名去重
#       name_to_idx[dem] = len(name_table)

# 数据库存储时按 (so_id, func_id, func_type) 去重
so_func_rows = list(set(so_func_rows))
```

**特点**：
- 多个 mangled 名指向同一 demangled 名时被合并为 1 个
- D0/D1/D2 析构函数被计为 1 个
- 模板实例化的不同特化版本可能被合并


## 三、差异来源

### 析构函数别名

C++ 编译器为每个类生成多个析构函数符号：

| Mangled 名 | 含义 | Demangled 名 |
|-----------|------|-------------|
| `_ZN4OHOS10ParcelableD0Ev` | 完整析构 (Complete destructor) | `OHOS::Parcelable::~Parcelable()` |
| `_ZN4OHOS10ParcelableD1Ev` | 删除析构 (Deleting destructor) | `OHOS::Parcelable::~Parcelable()` |
| `_ZN4OHOS10ParcelableD2Ev` | 基类析构 (Base destructor) | `OHOS::Parcelable::~Parcelable()` |

三个 mangled 名不同，但 demangle 后名字相同。按 mangled 去重计 3 个，按 demangled 去重计 1 个。

### 虚表 thunk 函数

```cpp
// 多继承场景下，虚表调整 thunk
_ZThn120_N4OHOS9AccountSA15IDMCallbackStubD1Ev
_ZThn120_N4OHOS9AccountSA15IDMCallbackStubD0Ev

// demangle 后可能指向同一函数
```

### 模板实例化

不同编译单元中的相同模板特化，COMDAT 折叠后地址相同，但符号名可能不同（ABI 前缀差异）。


## 四、哪种更合理

### 结论：按原始符号名（mangled）去重更合理

**理由**：

1. **函数入口独立性**
   - 每个 mangled 名对应一个独立的函数入口地址
   - D0 和 D1 是不同的函数，各有自己的 prologue/epilogue
   - 各自需要独立的 PAC 签名/认证、CFI 类型检查、BTI 着陆垫

2. **安全评估准确性**
   - 覆盖率 = 受保护函数数 / 总函数数
   - 如果总函数数少计（demangled 去重），覆盖率会被高估
   - 例如：9/84 = 10.7%（mangled） vs 9/78 = 11.5%（demangled）

3. **代码保护完整性**
   - 每个函数入口都需要保护
   - 漏掉任何一个入口都是安全风险
   - 按 mangled 计数确保不遗漏

4. **与检测逻辑一致**
   - `classify_functions()` 按 mangled 去重 → 覆盖率计算
   - `_scan_pac_bti_functions()` 按 mangled 去重 → PAC/BTI 覆盖率
   - `scan_call_sites()` 按指令扫描 → vcall/icall 检测
   - 全部基于原始符号，保持一致

### 按 demangled 去重的合理性

仅在**展示场景**下合理：
- 避免重复显示相同名字的函数
- 用户看到 `OHOS::Parcelable::~Parcelable()` 出现 3 次会困惑
- 但不应影响计数和覆盖率计算


## 五、各检测环节的去重方式

| 检测环节 | 函数 | 去重方式 | 用途 |
|---------|------|---------|------|
| CFI 函数分类 | `classify_functions()` | mangled 名 (set) | 覆盖率计算 ✅ |
| PAC/BTI 函数分析 | `_scan_pac_bti_functions()` | mangled 名 (set) | PAC/BTI 覆盖率 ✅ |
| 函数名 demangle | `build_module_data()` | demangled 名 (name_to_idx) | 展示用 |
| 数据库存储 | `generate_sqlite()` | demangled 名 (func_id) + (so_id, func_id, func_type) | 展示用 |
| 弹窗标题（修复前） | `openFuncModal()` | 用 classify 的 mangled 计数 | 与列表不一致 ❌ |
| 弹窗标题（修复后） | `openFuncModal()` | 用 API 实际返回数量 | 与列表一致 ✅ |


## 六、Excel 中的函数总数

### CFI 函数总数

```
Excel "函数总数" = cfi_protected_count + truly_unprotected_count
                = len(set of mangled names with .cfi) + len(set of mangled names without .cfi)
```

- 去重方式：mangled 名（set 去重）
- **正确**：每个 mangled 名对应一个独立函数

### PAC/BTI 函数总数

```
Excel "PAC函数总数" = pac_func_protected + pac_func_sign_only + pac_func_no_pac
                    = 按函数名（mangled）去重后的函数总数
```

- 去重方式：mangled 名（`seen_names` set 去重）
- **正确**：与 CFI 函数总数去重方式一致

### 两者关系

```
PAC/BTI 函数总数 = CFI 函数总数 + CFI 基础设施函数数
```

- CFI 函数总数不含 `.cfi` 后缀函数和 `__cfi*` 基础设施
- PAC/BTI 函数总数不含 `.cfi` 后缀函数，但含 `__cfi*` 基础设施
- 差异 = `__cfi*` 基础设施函数数（通常 2-4 个）


## 七、修复方案

### 弹窗标题修复

**问题**：弹窗标题显示 classify 的 mangled 计数（84），但列表是数据库的 demangled 计数（78），不一致。

**修复**：API 返回后，用实际返回的函数数量更新标题：

```javascript
// 修复前：用预存计数
html += '<h4>'+sec.label+' ('+sec.count+' 个)</h4>';  // 84

// 修复后：先显示标题，API 返回后更新
html += '<h4 id="hdr_'+sec.type+'">'+sec.label+'</h4>';
// ...
funcs = await fetchJSON(API+'/api/so_files/'+soId+'/functions?type='+sec.type);
hdr.textContent = sec.label+' ('+funcs.length+' 个)';  // 78，与列表一致
```

### 彻底修复（未实施）

要让数据库存储的函数名数量与 mangled 计数一致，需要：

1. `name_table` 按 mangled 名存储索引（不 demangle）
2. `so_functions` 按 (so_id, func_id, func_type) 去重，func_id 为 mangled 名索引
3. API 返回 mangled 名，前端按需 demangle 展示

**影响**：
- `name_table` 行数增加（mangled 名比 demangled 名多）
- SQLite 体积增大
- 但计数和覆盖率计算完全一致

**当前折中方案**：
- 覆盖率计算用 mangled 计数（正确）
- 弹窗显示用 demangled 计数（与列表一致，用户友好）
- 两者用途不同，各自合理


## 八、总结

| 问题 | 结论 |
|------|------|
| 哪种去重更合理 | 按原始符号名（mangled）去重 |
| Excel 函数总数用的哪种 | mangled 去重 ✅ |
| 覆盖率计算用的哪种 | mangled 去重 ✅ |
| 弹窗显示用的哪种 | demangled 去重（与列表一致）|
| 两者差异原因 | D0/D1/D2 析构函数、虚表 thunk、模板特化 |
| 是否需要彻底修复 | 不需要，当前折中方案合理 |
