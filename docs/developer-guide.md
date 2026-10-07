# 开发手册

## 1. 环境与命令

当前运行环境：macOS 27.2 arm64、Python 3.13.13、PySide6 Essentials 6.11.2。源码声明 Python >=3.11，`.python-version` 选择 3.13；`uv.lock` 锁定解析结果。尚未验证其他 Python/OS 组合。

```sh
uv sync --frozen --extra dev
uv run --frozen sdes-lab
uv run --frozen --extra dev pytest -q --cov=sdes
uv run --frozen --extra dev ruff check .
uv run --frozen --extra dev ruff format --check .
uv run --frozen python collect_evidence.py
```

## 2. 模块与依赖

| 模块 | 职责 |
|---|---|
| constants.py | 置换表、S 盒及算法版本 |
| core.py | 位运算、轮密钥、分组/字节加解密、实际轮轨迹 |
| codecs.py | 严格位串、ASCII 与 Hex 转换，字节预览 |
| analysis.py | 完整搜索、分桶统计、进度、取消及计时 |
| export.py | 临时文件写入和原子替换，JSON/CSV 数据 |
| workers.py | QThread 计算任务、信号及取消事件 |
| gui.py | 四个标签页、校验反馈、结果和导出交互 |
| __main__.py | 应用入口 |
| collect_evidence.py | 可复现数值证据，不生成组间测试结果 |

算法核心不依赖 Qt。分析层复用核心的轮密钥和加密内核。界面只解析输入、发起操作和显示结果。Python 使用 snake_case，公共算法接口标注类型；复杂位序和算法决策保留必要注释。

## 3. 算法版本与测试向量

唯一运行版本标识为 `shimo-direct-ls2-v1`，对应设计文档转换表和从 P10 原始两半分别左移 1、2 位的 K1/K2。此决定来自作业公式的字面解释。本组已与三点水小组完成组间测试（项目成员确认）；具体测试记录待补充，教师对位移规则的确认未登记。SBox2 行 `10`、列 `11` 的值为 `2`。

固定向量手工推导：

```text
主密钥 = 1010000010
P10    = 10000 | 01100
LS1    = 00001 | 11000   → K1 = 10100100
LS2    = 00010 | 10001   → K2 = 10010010（从 P10 原始结果计算）
明文   = 11010111
IP     = 11011101
轮1    = 00101101
SW     = 11010010
轮2    = 10110010
密文   = 11101000
```

这个非周期密钥能够区分两种位移解释：累计 3 位的 K2 为 `01000011`，对应密文 `10101000`。获取课程参考后，若须变更规则，必须更新算法版本、子密钥、固定向量、全部证据和文档，并重新交叉验收。

采用直接 LS2 时，P10 后左半的第 3 位分别变为左移结果中的第 2/1 位，两者都未被 P8 选中。它对应主密钥从左数第 2 位，因此 `K` 与 `K XOR 256` 的两个轮密钥相同。测试覆盖该等价关系，不能把它误当作破解返回两个候选的程序缺陷。

## 4. 核心与格式接口

| 接口 | 返回与约束 |
|---|---|
| derive_subkeys(key) | tuple[int,int]，密钥整数 0–1023，两个 8 位轮密钥 |
| encrypt_block(block,key) / decrypt_block(block,key) | 0–255 整数；不接受 bool、负数或越界参数 |
| encrypt_bytes(data,key) / decrypt_bytes(data,key) | bytes，逐字节处理，保留长度；空输入合法 |
| trace_block(block,key,operation) | BlockTrace，operation 为 encrypt/decrypt |
| parse_bits(text,width) | 定长 0/1 字符串转整数，去除首尾空白 |
| parse_hex(text) | bytes，接受完整字节间空白，拒绝半字节和非法字符 |
| ascii_bytes(text) | bytes，非 ASCII 抛 ValueError 并指出位置 |
| preview_bytes(data) | 可打印 ASCII 加字节转义的字符串 |

底层 `permute` 和 `sbox_lookup` 供内部运算使用，输入由上层验证。查表来自相同 `_round` 逻辑；trace 和快速加解密须始终一致。轮密钥缓存上限 1024，轮函数和置换查表在导入时生成。

## 5. 分析接口与模型

`brute_force(pairs, progress=None, cancelled=None)`：至少一组 `(P,C)`；重复对去重，同一 P 对不同 C 抛 ValueError。返回全部满足约束的密钥，而非首个匹配。

`analyze_plaintext(block, ...)`：返回密文到密钥元组的桶映射、检查数和碰撞指标。

`analyze_all_plaintexts(...)`：返回 256 个明文的摘要和碰撞实例；未完成的当前明文不计入完整统计行，但已检查密钥数量保留。

`AnalysisResult` 为 SearchResult / CollisionResult / FullAnalysisResult 联合类型，任务使用 AnalysisTask Protocol，统计行使用 CollisionRow TypedDict。结果包含状态、北京时间开始/结束时间及单调时钟耗时。运行时北京时间采用固定 UTC+08:00，避免依赖系统 IANA 数据库。

`progress(checked,total)` 在迭代边界报告；`cancelled()` 每个密钥检查。只有完整检查 1024 个密钥或完成 256 个分组时状态为 complete，其余中止结果为 cancelled。

计时从输入验证后、本次计算开始前记录，覆盖本次密钥生成/缓存查询、枚举及进度回调，不包含应用启动和静态查表生成、界面绘制、导出。不同运行可能有不同的缓存和线程调度开销，GUI 与命令行耗时不能直接作为加速比较。

## 6. GUI 线程与保存

AnalysisJob 的 run 只执行计算，用信号将结果传回主线程的 Slot。取消采用 threading.Event；任务完成后保留结果、解除禁用、移除线程引用并 deleteLater。关闭窗口时先请求取消，使用 QTimer 等待线程退出后关闭。

输入错误会清空旧结果，防止误导出；任务失败记录异常并在界面显示。导出先写同目录临时文件，再 os.replace；失败清理临时文件并传播错误。

实际验收中 macOS 原生文件面板没有采用指定起始目录，现使用 Qt 自带 QFileDialog，并明确指定默认证据目录；已通过真实窗口操作保存 JSON 并读取核对。

Qt 线程实现参考官方 [QThread 文档](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThread.html)及[线程与信号示例](https://doc.qt.io/qtforpython-6/examples/example_widgets_thread_signals.html)。

## 7. 导出与验证边界

JSON 字段包含 algorithm、app_version、kind、environment、result。算法数据保持整数和精确字节语义；状态必须一并保留。

CSV 每行包含 algorithm、status、时间戳、耗时和该类型的结果；搜索额外包含全部输入对，例如 `11010111:11101000`，多个对用分号连接。二进制文本固定宽度。JSON 是精确环境与数据来源，CSV 适于表格展示。

自动测试包含独立手算向量、全密钥/分组往返、全部 S 盒索引、格式边界、搜索完整性、碰撞计数、导出、GUI 后台完成/取消/失败状态。注入异常只验证错误处理；不能用它证明真实算法或组间兼容。

真实桌面截图及文件保存见测试报告。源码和材料已上传至 [GitHub 公开仓库](https://github.com/yoyuzh/sdes-lab)（2026-10-07）；与三点水小组的组间测试已完成，作业提交尚未完成。
