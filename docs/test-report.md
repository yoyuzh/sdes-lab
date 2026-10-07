# S-DES 第一版测试报告

日期：2026-10-06。版本：0.1.0。环境：macOS 27.2 arm64、Python 3.13.13、PySide6 Essentials 6.11.2。算法：`shimo-direct-ls2-v1`。

## 总体结果

第一版已实现并在当前电脑启动。32 项自动测试通过，应用代码覆盖率 91%。全部 1024 个密钥 × 256 个明文的 262144 种组合均通过往返和单密钥置换检查。实际桌面的二进制/ASCII 加解密、破解、单/全明文分析和文件保存已验证。

课堂兼容性仍待确认：本版按源文档公式从 P10 结果分别左移 1、2 位。真实其他组交叉测试未执行，本机往返不能替代互操作验收。

## 固定向量

参数按[原题](https://shimo.im/docs/m5kvdlMaKvcENy3X)转录。S1 第三行是 `(3,0,1,2)`，行 `10`、列 `11` 的值为 2。完整参数见[设计文档](design.md)。下表由设计阶段手算推导，在核心测试与实际 GUI 核对；不是其他组的独立结果。

| 步骤 | 二进制 |
|---|---|
| 密钥 | `1010000010` |
| K1 / K2 | `10100100` / `10010010` |
| 明文 | `11010111` |
| IP 后 | `11011101` |
| 第一轮后 | `00101101` |
| 交换后 | `11010010` |
| 第二轮后 | `10110010` |
| 密文 | `11101000` |

累计左移 3 位规则会得到密文 `10101000`，可用于与课堂或其他组核对。[穷举及轮中间值](../evidence/basic/exhaustive.json)。

## 五关验收

| 关卡 | 状态 | 证据 |
|---|---|---|
| 基本测试 | 固定向量、校验和全空间往返通过 | [加密截图](../evidence/basic/gui-encrypt.png)、[解密截图](../evidence/basic/gui-decrypt.png)、[穷举记录](../evidence/basic/exhaustive.json) |
| 交叉测试 | 待其他组实际验证 | [登记说明](../evidence/cross/README.md) |
| 字符串扩展 | ASCII 加密与 Hex 解密恢复原文，非法输入拒绝 | [结果](../evidence/text/roundtrip.json)、[加密截图](../evidence/text/gui-encrypt.png)、[解密截图](../evidence/text/gui-decrypt.png) |
| 暴力破解 | 单对/多对完整检查 1024 个密钥，返回全部候选；后台执行与保存通过 | [GUI 导出](../evidence/bruteforce/gui-search.json)、[保存截图](../evidence/bruteforce/gui-saved.png)、[演示 GIF](../evidence/bruteforce/demo.gif) |
| 碰撞分析 | 单明文与全部 256 个明文分析完成，GUI 展示统计 | [单明文截图](../evidence/collision/gui-single.png)、[全明文截图](../evidence/collision/gui-all.png)、[完整结果](../evidence/collision/all-plaintexts.json) |

ASCII 输入 `Hello, S-DES!`，密钥 `1010000010`，得到 `E4 5C 89 89 AB DD C2 CB 56 9B 30 CB AD`，解密恢复原文。

## 分析结论与计时

输入对 `(215,232)` 的候选为 `180,436,603,642,859,898`。用密钥 642 生成明文 0–15 的 16 对输入，候选缩小为 `642,898`。[单对](../evidence/bruteforce/single-pair.json)、[多对](../evidence/bruteforce/multiple-pairs.json)。

直接左移 2 位的密钥计划不使用主密钥从左数第二位，因此 K 与 `K XOR 256` 的子密钥相同。测试核对全部 512 对等价密钥，并对 642/898 的全部 256 个明文比较密文；增加输入对无法区分该等价密钥对。

每个固定明文的 1024 个密钥产生 254 个不同密文，254 个桶均有多把密钥，最大桶大小为 8；全部 256 个明文存在碰撞。[汇总](../evidence/summary.json)、[完整 CSV](../evidence/collision/all-plaintexts.csv)。

计时使用 `perf_counter`，排除启动、绘制和导出。实际 GUI 单对搜索截图/GIF 对应运行是 17.739 ms；保存 JSON 对应另一轮是 21.501 ms。GUI 全明文分析 138.129 ms；数值脚本全明文分析 79.010 ms。缓存、信号回调和调度影响结果，以上只代表当前电脑测量。

GIF 是实际开始/完成截图合成的 9 秒演示，**不是连续录屏**，播放长度不代表破解耗时。

## 测试记录

```bash
uv run --frozen --extra dev pytest -q --cov=sdes --cov-report=term-missing --cov-report=json:evidence/basic/coverage.json --junitxml=evidence/basic/pytest.xml
uv run --frozen --extra dev ruff check .
uv run --frozen --extra dev ruff format --check .
```

结果：`32 passed in 2.02s`，Ruff 检查通过，20 个文件格式检查通过。核心、编解码、导出覆盖率 100%，GUI 90%，分析模块 97%，总计 91%。[JUnit](../evidence/basic/pytest.xml)、[覆盖率](../evidence/basic/coverage.json)。

测试覆盖轮计算、所有 S 盒项、全空间往返、校验、搜索、取消/部分结果、统计、原子导出、异常传播、Qt 后台任务与失效结果清理。实际桌面保存后重新读取 JSON，确认输入对、检查量、候选和完整状态已落盘。最终 Python 代码只读复核通过。

取消行为通过 Qt 集成测试；实际桌面分析很快完成，本次未取得任务进行中点击取消的人工记录。异常场景也由集成测试验证。

## 剩余工作

课堂位移约定与真实组间互操作待确认。其他操作系统未实际验收；提交表登记未执行。TCP、UTF-8 扩展和独立安装包未实现。作业截止：2026-10-08 23:00（北京时间）。

发布补记（2026-10-07）：源码、文档、测试与证据已上传至 [GitHub 公开仓库](https://github.com/yoyuzh/sdes-lab)。本次发布没有改变上述 2026-10-06 的算法验收结果。
