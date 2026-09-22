# hash-verify · 多算法哈希校验工具

> 一个**单文件、零依赖、可离线**的浏览器端文件哈希校验器：拖入文件 + 拖入 `SHA256SUMS` 之类的校验清单，立刻告诉你文件是否被篡改或下载损坏。文件**不会上传**，页面**不发任何网络请求**。

![完全本地](https://img.shields.io/badge/100%25-本地运行-success)
![零依赖](https://img.shields.io/badge/dependencies-0-brightgreen)
![单文件](https://img.shields.io/badge/single--file-61.7%20KB-blue)
![离线可用](https://img.shields.io/badge/works-offline-informational)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**在线使用（免下载）：** <https://yhz73194862.github.io/hash-verify_HTML/>

---

## 为什么需要它

从官网/镜像站下载 `setup.exe`、`xxx.iso`、`xxx.zip` 之后，官方通常给出一个 `SHA256SUMS` 文件。核对它有三种常见做法，但都不太顺手：

| 做法 | 痛点 |
| --- | --- |
| `sha256sum -c SHA256SUMS` | Windows 上没有这个命令；路径/编码/文件名空格稍有出入就报 `FAILED open or read` |
| `certutil -hashfile file.exe SHA256` | 只支持 MD5/SHA-1/SHA-2 系列；输出的哈希还要自己肉眼比对，中文文件名显示乱码 |
| 各种在线校验网站 | **必须把文件上传到别人的服务器**，对安装包、内部资料完全不可接受 |

本工具把这件事变简单：**本地算、自动比对、红绿一眼可见**，并且支持一次比多种算法、识别多种清单格式与编码。

## 特性

- **9 种哈希算法**：MD5、SHA-1、SHA-224、SHA-256、SHA-384、SHA-512、SHA3-256、BLAKE2b-512、CRC32，可自由多选
- **一遍读取算完所有算法**：多选时不会重复读文件；已算过的结果会缓存，临时勾选新算法只补算缺的那一种
- **校验清单解析**：兼容 GNU `sha256sum`、BSD/OpenSSL `SHA256 (file) = hash`、Windows `certutil` 输出、二进制标记 `hash *file`、裸哈希值、`#` 注释；**按哈希长度自动识别算法**，一份清单里可混放多种算法
- **编码可选**：UTF-8 / GBK(GB18030) / Big5 / Shift-JIS / UTF-16LE —— 中文文件名的清单常是 GBK
- **完全本地**：零网络请求、无遥测；双击 `file://` 打开即可用，可断网
- **大文件友好**：≤512 MB 走浏览器原生 `crypto`（最快），更大或强制流式时切换内置 JS 引擎分块计算，**内存占用恒定**，带进度、耗时
- **结果一目了然**：逐算法列出「计算值 / 清单值」并标 `✓`/`✗`，整体区分为 校验通过 / 部分通过 / 不匹配 / 未找到记录，可「只看异常项」
- **导出**：复制校验和、下载 `SHA256SUMS` / `MD5SUMS` / `SHA512SUMS`…（不带 BOM，可直接 `sha256sum -c`）、下载详细 `.txt` 报告
- **单文件交付**：一个 `.html` 就是全部，便于放进 U 盘、随安装包分发、内网共享
- 响应式布局，自动跟随系统深/浅色主题

## 快速开始

### 方式一：直接下载使用（推荐）

1. 从 [Releases](../../releases) 下载 `hash-verify.html`（或把仓库里的 `index.html` 另存为本地文件）
2. 双击用浏览器打开（无需安装、无需联网）
3. 把文件拖进第 1 步，把 `SHA256SUMS` 拖进第 2 步，看第 3 步的红绿灯

### 方式二：在线使用（GitHub Pages）

仓库根目录的入口文件名为 `index.html`（即应用本体），开启 `Settings → Pages → Deploy from a branch → main / (root)` 后即可直接访问：

```
https://yhz73194862.github.io/hash-verify_HTML/
```

> 页面本身不发网络请求，所有计算都在你的浏览器里完成；在线版和本地版行为完全一致。

### 方式三：本地起个静态服务（可选）

```bash
# 其实非必需，file:// 直接打开也可以
python -m http.server 8080
# 然后访问 http://localhost:8080/index.html
```

## 使用步骤

1. **选择文件与算法** —— 拖入待校验文件（可多选），勾选需要的哈希算法（默认 SHA-256）
2. **载入校验清单（可选）** —— 拖入 `SHA256SUMS` / `MD5SUMS` / `*.txt`，或直接粘贴清单内容；文件名、扩展名、内容任一来源都能识别。**不提供清单时，本工具就是一台多算法哈希计算器。**
3. **看结果** —— 每行显示各算法的计算值与清单值，命中显示 `✓`，不符显示 `✗` 并给出期望值

## 支持的算法

| 算法 | 哈希长度 | 实现 | 清单文件名习惯 |
| --- | --- | --- | --- |
| MD5 | 32 | JS 引擎 | `MD5SUMS` |
| SHA-1 | 40 | 原生 `crypto` + JS 回退 | `SHA1SUMS` |
| SHA-224 | 56 | JS 引擎 | `SHA224SUMS` |
| SHA-256 | 64 | 原生 `crypto` + JS 回退 | `SHA256SUMS` |
| SHA-384 | 96 | 原生 `crypto` + JS 回退 | `SHA384SUMS` |
| SHA-512 | 128 | 原生 `crypto` + JS 回退 | `SHA512SUMS` |
| SHA3-256 | 64 | JS 引擎（Keccak-f[1600]） | `SHA3SUMS` |
| BLAKE2b-512 | 128 | JS 引擎 | `BLAKE2SUMS` |
| CRC32 | 8 | JS 引擎 | `CRC32SUMS` |

> 「原生」指浏览器 `crypto.subtle`，速度最快；MD5 / CRC32 / SHA3 / BLAKE2b 没有原生实现，使用内置纯 JS 引擎。SHA-512 / SHA3 / BLAKE2b 的 JS 实现基于大整数运算，速度明显低于 SHA-256，GB 级文件请耐心等待或只勾选必要的算法。

## 支持的校验清单格式

```text
# 注释行，以 # 或 ; 开头
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592  app-windows-x64.exe   # GNU，两个空格
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592 *app-windows-x64.exe   # 二进制模式标记
9e107d9d372bb6826bd81d3542a419d6  app-windows-x64.exe                                    # MD5，按长度识别
SHA512 (some.iso) = 8e959b75dae313da8cf4f72814fc143f...                                   # BSD / OpenSSL
MD5 hash of file C:\downloads\setup.exe:                                                  # Windows certutil
9e107d9d372bb6826bd81d3542a419d6
352441c2  tiny.cfg                                                                        # CRC32
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592                          # 裸哈希 = 通用期望值
```

配套的命令行写法对照：

```bash
# Linux / macOS
sha256sum -c SHA256SUMS
# Windows PowerShell
Get-FileHash .\app.exe -Algorithm SHA256
# Windows CMD
certutil -hashfile app.exe SHA256
```

## 常见问题

**Q：文件名不一致怎么办（比如清单写 `./dist/app.exe`，我只有 `app.exe`）？**
先按“相对路径”比对，再退回按“文件名”比对，两侧都忽略大小写、统一 `/` 与 `\`，`./` 前缀会被忽略。

**Q：只粘贴了一个哈希值能用吗？**
可以。没有文件名的裸哈希会被当作**通用期望值**，与加入的文件逐一比对，适合只校验一个文件的场景。

**Q：64 位和 128 位的哈希怎么区分算法？**
清单里写了算法名（BSD 或 certutil 格式）就按名称匹配；只写哈希值时按长度识别。64 位可能是 SHA-256 或 SHA3-256、128 位可能是 SHA-512 或 BLAKE2b-512，**同长度时按长度匹配，任一对上即通过**。

**Q：中文文件名显示乱码 / 明明没错却提示未找到？**
校验清单多半是 GBK 编码，请在「清单编码」里选 `GBK / GB18030` 后重新拖入清单。

**Q：为什么要选编码？不能自动猜吗？**
可以自动猜，但猜错会静默导致比对失败，不如让你显式选一次更可靠。

**Q：`MISMATCH`（不匹配）一定是文件被篡改了吗？**
不一定。按概率排序：① 清单选错了版本/平台；② 下载中断导致文件不完整；③ 磁盘或传输损坏；④ 清单本身被替换。先重新下载，再核对清单来源。

**Q：和 GPG 签名校验什么关系？**
本工具只做哈希一致性校验。如果官方同时提供 `.sig`/`.asc` 签名，请用 GPG 校验签名——**哈希值本身无法证明来源可信**。

**Q：会不会偷偷上传我的文件？**
不会。页面没有任何 `fetch`/`XMLHttpRequest`/WebSocket，也没有第三方脚本、字体或图标 CDN。你可以断网打开页面、在 DevTools 的 Network 面板确认零请求，或直接读全部源码（只有一个 HTML 文件）。

**Q：为什么没有 SHA3-512 / SHAKE / BLAKE3 / SM3？**
体积与收益的取舍。这些算法在公开校验清单里出现频率很低；BLAKE3 与 SM3 需要额外实现且缺少浏览器原生支持。欢迎 PR。

**Q：支持“原始 Keccak”（以太坊那种）吗？**
不支持。本工具实现的是 **NIST FIPS 202 的 SHA-3**，与早期原始 Keccak 的填充不同，两者结果不一样。

## 浏览器支持

| 浏览器 | 状态 |
| --- | --- |
| Chrome / Edge 86+ | ✅ 支持 |
| Firefox 78+ | ✅ 支持 |
| Safari 15+ | ✅ 支持 |
| 国产浏览器（Chromium 内核） | ✅ 支持 |

原生 `crypto.subtle` 在 `file://` 下多数浏览器视为安全上下文可用；若不可用（或文件超过 512 MB），会自动回退到内置纯 JS 分块引擎，功能不受影响。

## 正确性验证

哈希实现写错一个常数就会静默给出**看起来很正常**的错误结果——所以本仓库自带一套已知答案测试（KAT），并对接独立参照实现交叉验证：

```bash
node test/kat.mjs      # 需要 Node.js ≥ 20（用到 zlib.crc32）
```

测试覆盖：

- **MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 / CRC32**：与 Node 内置 `crypto`、`zlib.crc32` 逐字节对比，长度 0–200 字节穷举 + 1 KB / 64 KB / 200 KB 随机数据
- **SHA3-256**：使用操作系统自带的 `certutil -hashfile … SHA3-256`（Windows）作为**独立实现参照**，覆盖 1、3、55、100、135、136、137、200、271、272、273、500、4096、100000 字节（含跨块与多块），另加 FIPS 202 官方向量
- **BLAKE2b-512**：RFC 7693 官方向量 + 仓库内一份**结构不同的独立参考实现**（显式切块、单独处理末块标志与字节计数器）对 127/128/129/255/256/257 等边界尺寸比对
- **流式正确性**：9 种算法 × 19 种尺寸随机分块投喂，再对 6000 字节做逐字节喂入，结果必须与一次性计算一致
- **清单解析器**：混合算法、GNU / BSD / `*` 标记 / 裸哈希 / certutil / 注释 / 非法行 / BOM 共 20 项断言

当前状态：**1687 项断言全部通过**。开发过程中正是靠多块对拍抓出了 BLAKE2b 计数器更新时机错误（≥129 字节结果全错），详见提交记录。

> Windows 上如果没有 Node.js，也可以用本工具自身核对：把 `index.html` 与 `SHA256SUMS` 一起拖进页面即可。

## 项目结构

```text
.
├── index.html         # 全部功能：UI + 样式 + 哈希引擎 + 清单解析（单文件，无构建）
├── test/
│   └── kat.mjs        # 已知答案测试与交叉对拍脚本（Node.js；也支持 hash-verify.html 这个名字）
├── SHA256SUMS         # 仓库文件自校验清单：sha256sum -c SHA256SUMS
├── README.md
└── LICENSE            # MIT
```

## 发布建议（仓库维护者）

把应用作为 **Release 资产**发布，并顺手用它校验自己，形成闭环：

```bash
# 1) 生成清单（或直接用本工具界面导出 SHA256SUMS）
sha256sum index.html > SHA256SUMS        # 仓库自校验用，条目名与仓库文件名一致
# 2) 作为 Release 资产时，把 index.html 以 hash-verify.html 为名上传
#    （附件名与清单条目名一致，使用者才能直接 sha256sum -c 核对）
# 3) 使用者下载附件与 SHA256SUMS 放在同一目录后核对
```

## 贡献

欢迎提交 Issue / PR。改动哈希引擎时，请确保 `node test/kat.mjs` 全绿，并说明新增测试覆盖的边界情况。

## 免责声明

- 校验通过只能说明**文件与清单内容一致**；若清单本身来自不可信渠道，结论同样不可信。请从官方 HTTPS 站点或签名渠道获取清单。
- MD5 与 SHA-1 已不具备抗碰撞能力，**仅适用于校验下载完整性**，不可用于签名、口令存储等安全场景。需要抗碰撞时请使用 SHA-256 及以上。
- 本工具不提供任何担保，请自行评估是否用于生产流程。

## License

[MIT](LICENSE)

---

## English

**hash-verify** is a single-file, zero-dependency, offline-capable hash checker that runs entirely in your browser. Drop a file and a `SHA256SUMS`-style manifest onto the page and it tells you whether they match — nothing is uploaded, and the page makes no network requests at all.

- **9 algorithms**: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b-512, CRC32 (multi-select supported)
- **Manifest formats**: GNU `sha256sum`, BSD/OpenSSL `SHA256 (file) = hash`, Windows `certutil` output, `hash *file`, bare hashes, comments; the algorithm is inferred from the hash length, so mixed manifests work
- **Encodings**: UTF-8 / GBK / Big5 / Shift-JIS / UTF-16LE
- **Fast & memory-safe**: native WebCrypto for ≤512 MB, built-in streaming JS engine beyond that
- **Usage**: download `hash-verify.html` from [Releases](../../releases), or open <https://yhz73194862.github.io/hash-verify_HTML/>
- **Verification**: `node test/kat.mjs` — 1687 assertions cross-checked against Node's `crypto`, `zlib.crc32`, and OS-provided `certutil` (as an independent SHA-3 reference)

> MD5 and SHA-1 are cryptographically broken; use them only for download-integrity checks. A matching hash proves the file matches the manifest — it does **not** prove the manifest itself is trustworthy.
