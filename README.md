# iosbackup-decrypt

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![tests](https://github.com/WhiteAshura/ios-backup-decryptor/actions/workflows/tests.yml/badge.svg)](https://github.com/WhiteAshura/ios-backup-decryptor/actions/workflows/tests.yml)

**纯 Python 的 iOS / iPadOS 加密备份解密与浏览工具。** 不需要越狱、不需要 iTunes 类客户端、不依赖任何外部二进制——只要你知道自己备份的密码。

> 仓库：<https://github.com/WhiteAshura/ios-backup-decryptor>

它做两件事：

1. 解密加密备份里的 **`Manifest.db`**（文件清单，现代 iOS 上整库加密）；
2. 按清单解密备份里**任意一个文件**（每个 App 容器、每个 domain 都能单独取）。

```bash
pip install iosbackup-decrypt

iosbackup-decrypt info                      # 设备信息 + 验证密码
iosbackup-decrypt domains --limit 20        # 有哪些 App 数据域
iosbackup-decrypt ls --domain AppDomain-com.example.app
iosbackup-decrypt extract --domain AppDomain-com.example.app --out ./dump
```

---

## 目录

- [特性](#特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [命令参考](#命令参考)
- [Python API](#python-api)
- [原理](#原理)
- [常见问题](#常见问题)
- [安全与隐私](#安全与隐私)
- [开发与测试](#开发与测试)
- [免责声明](#免责声明)
- [English](#english)

---

## 特性

- **纯 Python**：只依赖 `pycryptodome`，Windows / macOS / Linux 都能跑。
- **不碰设备**：直接读磁盘上的备份文件夹（Finder / iTunes / iMazing 做的都行）。
- **兼容面广**：iOS 10.2+ 的双阶段 PBKDF2 keybag（`DPSL` / `DPIC`）、新版 keybag `VERS=5`、以及 iOS 10.0–10.2 时代**未加密**的 `Manifest.db` 都支持。
- **大备份友好**：2.4 GB 的 `Manifest.db` 流式解密约 4 秒；解出的副本按（大小, mtime）指纹缓存，并自动建 domain 索引，之后按 App 查文件是毫秒级。
- **流式解密单文件**：不会把 700 MB 的视频整个读进内存。
- **CLI + 库**：命令行够用，也可以 `from iosbackup_crypto import Backup` 当库调。
- **明确告警**：备用里被截断的文件、缺失 class key 的文件都会提示，而不是静默出错。

## 安装

```bash
# 从源码（推荐，能看到它到底做了什么）
git clone https://github.com/WhiteAshura/ios-backup-decryptor.git
cd ios-backup-decryptor
pip install -e .

# 或者只要依赖、不装包
pip install pycryptodome
PYTHONPATH=src python -m iosbackup_crypto info
```

要求 Python >= 3.9。

## 快速开始

先找到备份目录：

| 平台 | 位置 |
|---|---|
| Windows | `%APPDATA%\Apple Computer\MobileSync\Backup` |
| macOS | `~/Library/Application Support/MobileSync/Backup` |
| iMazing（自定义位置） | 例如 `~/Apple/MobileSync/Backup` |

里面通常是 `<UDID>` 文件夹，`Manifest.plist` 就在其中。工具既能接受父目录（自动发现 UDID），也能接受 UDID 目录本身。

```bash
# 1) 设备与备份信息（这一步就验证了密码对不对）
iosbackup-decrypt info
```

```
backup        C:\Users\me\AppData\Roaming\Apple Computer\MobileSync\Backup\00008140-001874481E3B001C
device        Parsifal
model         iPhone17,1
ios           27.0.1 (24A446)
udid          00008140-001874481E3B001C
last backup   2026-11-14 15:41:28
encrypted     yes
passcode set  yes
Manifest.db   2.3 GB
keybag        v5 / TYPE=1
pbkdf2        10,000 + 10,000,000 (SHA-256 stage)
classes       1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 17, 18, 19
```

```bash
# 2) 看有哪些数据域（App 容器 = AppDomain-<bundle id>）
iosbackup-decrypt domains --limit 20
```

```
   796,038  AppDomain-com.tencent.xin
   104,654  CameraRollDomain
    68,359  AppDomain-com.baidu.netdisk
    65,481  AppDomain-com.360buy.jdmobile
   ...
```

```bash
# 3) 列出某个 App 里的文件
iosbackup-decrypt ls --domain AppDomain-com.example.app
iosbackup-decrypt ls --domain AppDomain-com.example.app --path Documents --glob '*.sqlite'
```

```bash
# 4) 导出整个 App 容器（保留 Documents/... 目录结构）
iosbackup-decrypt extract --domain AppDomain-com.example.app --out ./dump

# 只导出某类文件、跳过超大文件
iosbackup-decrypt extract --domain AppDomain-com.example.app --glob '*.sqlite' --max-size 50 --out ./dump
```

```bash
# 5) 全库搜文件（按路径或文件名匹配）
iosbackup-decrypt find '*.sqlite' --limit 20
iosbackup-decrypt find 'Library/Preferences/*' --domain AppDomain-com.example.app
```

```bash
# 6) 直接打印一个小文件，或另存
iosbackup-decrypt cat --domain AppDomain-com.example.app --path Documents/config.json
iosbackup-decrypt cat --domain AppDomain-com.example.app --path Library/Preferences/x.plist -o x.plist
```

密码的四种给法（优先级从高到低）：

```bash
iosbackup-decrypt --password 'secret' info        # 会警告：进程列表可见
iosbackup-decrypt --password-file ~/.iosbak.pw info
IOS_BACKUP_PASSWORD='secret' iosbackup-decrypt info   # 推荐
iosbackup-decrypt info                            # 都没有则交互式输入
```

## 命令参考

| 命令 | 作用 |
|---|---|
| `info` | 设备/备份元信息；顺带验证密码。`--count` 会额外统计文件总数（慢） |
| `domains` | 列出数据域及文件数，按数量降序 |
| `ls --domain X` | 列出该域条目（大小、修改时间、路径），可加 `--path` / `--glob` |
| `find GLOB` | 按路径/文件名匹配，跨域搜索 |
| `extract` | 解密并落盘，默认保留 `domain/relativePath` 结构；`--flatten` 拍平 |
| `cat` | 打印单个文件（`-o` 存文件） |
| `check` | 只验证密码，不解密大文件 |
| `clean` | 删除缓存的解密副本 |

通用参数：`-b/--backup`、`--password`、`--password-file`、`--no-cache`、`--cache-dir`、`-v`、`--json`。

`extract` 在没有 `--domain/--path/--glob` 时会**拒绝执行**（避免手一抖导出 147 万个文件）。

## Python API

```python
from iosbackup_crypto import Backup

with Backup(r"C:\Users\me\AppData\Roaming\Apple Computer\MobileSync\Backup",
            password="secret") as bak:
    print(bak.info()["device_name"])

    for rec in bak.iter_files(domain="AppDomain-com.example.app", glob="*.sqlite"):
        print(rec.relative_path, rec.size)

    data = bak.read_file("AppDomain-com.example.app", "Documents/notes.txt")
```

常用成员：

| 成员 | 说明 |
|---|---|
| `bak.info(count_files=False)` | 设备/备份信息 dict |
| `bak.domains()` | `{domain: 文件数}` |
| `bak.iter_files(domain=, glob=, path_prefix=)` | 迭代 `FileRecord` |
| `bak.get_file(domain, path)` | 取单条 `FileRecord` |
| `bak.read_file(domain, path)` | 解密为 `bytes` |
| `bak.extract_file(record, target)` | 流式解密到磁盘，返回字节数 |
| `bak.extract(records, out_dir, flatten=False, max_size=None)` | 批量导出 |
| `bak.clear_cache()` | 清掉缓存的 `Manifest.db` |

## 原理

### 备份的结构

```
Backup/<UDID>/
├── Manifest.plist      # keybag + ManifestKey + 设备信息（永远不加密）
├── Manifest.db         # 文件清单，SQLite；现代 iOS 上整库加密
├── Status.plist
├── 00/ 01/ … ff/       # 文件内容，按 fileID 前两位十六进制分桶
│   └── <fileID>        # AES-256-CBC（零 IV）密文
```

`Manifest.db` 的 `Files` 表每行是 `fileID / domain / relativePath / flags / file`，其中 `file` 是一个 `NSKeyedArchiver` 编码的 `MBFile` 对象，里面装 `Size` 和 `EncryptionKey`。

### 两层密钥

**第一层：密码 → 类密钥（class key）**

`Manifest.plist` 的 `BackupKeyBag` 是一串 TLV 记录（tag 4 字节 ASCII + 长度 4 字节大端 + 值）：

```
VERS TYPE UUID HMCK WRAP SALT ITER DPWT DPIC DPSL        ← 头部
(UUID CLAS WRAP KTYP WPKY) * N                            ← 每个保护类一条
```

iOS 10.2 之后是两段式派生：

```
temp = PBKDF2-HMAC-SHA256(密码, DPSL, DPIC, 32)
dek  = PBKDF2-HMAC-SHA1(temp, SALT, ITER, 32)
```

更早的备份没有第一段，直接 `PBKDF2-HMAC-SHA1(密码, SALT, ITER)`。

然后对每个 `WRAP & 0x02`（由密码保护）的类，用 `dek` 做 **RFC 3394 AES 密钥解包** 得到该类密钥。密码错了会在这一步的完整性校验上失败。

**第二层：类密钥 → 文件密钥 → 明文**

```
ManifestKey        = 类编号(4 字节小端) || AES-KW(类密钥, Manifest.db 的密钥)
EncryptionKey      = 类编号(4 字节小端) || AES-KW(类密钥, 该文件的密钥)
明文               = AES-256-CBC 解密(密文, 文件密钥, IV=全 0)[:Size]
```

`Manifest.db` 解密后就是一个普通 SQLite；单个文件按 `Size` 截断（`Size` 缺失时才去剥 PKCS#7 padding）。

### 实现上的几个坑

- **keybag `VERS=5`** 的头部 `WRAP` 字段是 4 字节标志位，不是 40 字节被包裹的密钥——不能拿它做密码校验。
- **类密钥的 `WRAP` 标志位**：`0x01` 是用设备 UID 包裹的（备份里解不开，要跳过），`0x02` 才是密码保护。
- **`Manifest.db` 的尾部填充**：用 SQLite 头里的 page size × page count 精确截断，比盲剥 PKCS#7 稳。
- **`file` 列可能是两种编码**：现代是 `NSKeyedArchiver`（有 `$objects`），很老的是普通 plist dict，都要认。
- **有些文件的 `Size` 大于实际密文长度**（备份时文件被截断）。这类只能解出可读前缀，工具会告警。

## 常见问题

**Q：忘了备份密码怎么办？**
没有办法。AES-KW 的完整性校验 + 10,000,000 次 PBKDF2 就是为了防这件事的。只能重新做一份不加密的备份。

**Q：iCloud 备份能用吗？**
不能。iCloud 备份不在本地磁盘上，keybag 也不同，需要先下载到本地（且 iOS 不允许直接导出）。

**Q：这是越狱工具吗？不用连手机吗？**
不是，也不需要手机。它只读你磁盘上已有的备份文件夹。

**Q：能拿到 App 的 `Library/Caches` 吗？**
备份里没有就是没有——iOS 做备份时默认排除 `Library/Caches`。所以微信语音、抖音聊天图片这类缓存媒体，从备份里是取不到的。工具只能给你备份里真实存在的东西。

**Q：iOS 10 以前的备份（`Manifest.mbdb`）支持吗？**
不支持，会明确报错。那种格式的加密方式也不一样，用 [iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection) 那类老工具。

**Q：为什么第一次 `domains` 要几秒？**
因为要把 2.3 GB 的 `Manifest.db` 解密一遍并建索引。之后走缓存，是毫秒级。缓存位置：`%LOCALAPPDATA%\iosbackup-decrypt\<UDID>\`（macOS/Linux 在 `~/.cache/iosbackup-decrypt/`），可用 `clean` 删除，或 `--no-cache` 完全不用磁盘缓存。

**Q：和别家工具比？**
思路同源，都是社区逆向出来的格式：见 [iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection)（C/Python）、[iOSbackup](https://pypi.org/project/iOSbackup/)（纯 Python 库）、[iphone_backup_decrypt](https://github.com/mdegrazia/iphone_backup_decrypt)。本项目的定位是**一个能直接用的 CLI**：不用写代码就能 `ls/find/extract`，带缓存、索引、流式解密和截断告警。

## 安全与隐私

- **密码**：优先 `--password-file` 或 `$IOS_BACKUP_PASSWORD`；`--password` 会出现在进程列表里，工具会警告。密码不做任何持久化。
- **缓存**：`Manifest.db` 解密副本是**明文**地放在缓存目录里的（否则每次都要重解）。用完记得 `iosbackup-decrypt clean`，或全程加 `--no-cache`。
- **导出的文件**：`extract` 出来的都是明文，包含通讯录、聊天库、Token 之类的敏感内容，注意存放位置。
- 本工具不上传任何数据，全部逻辑在本地。

## 开发与测试

```bash
pip install -e '.[dev]'
pytest                       # 26 个测试，全部用合成备份，不需要真实数据
```

测试会现场造一个结构完全正确的加密备份（keybag / Manifest.db / 文件密文都用真实格式），所以 CI 里也能跑。

对真实备份做冒烟测试（需要你自己的备份密码）：

```bash
export IOS_BACKUP_PASSWORD='...'
python tools/real_backup_smoke.py "/path/to/MobileSync/Backup" AppDomain-com.tencent.xin
```

## 免责声明

本项目仅用于**恢复你自己设备、你自己备份**里的数据。使用他人设备或未经授权获取的数据可能违反法律。作者不对任何滥用负责。

## License

MIT，见 [LICENSE](LICENSE)。

---

## English

Pure-Python decryptor/browser for **encrypted iOS backups**. No jailbreak, no external binaries, no device needed — just the backup folder and its password.

```bash
pip install iosbackup-decrypt

iosbackup-decrypt info                          # device info; validates the password
iosbackup-decrypt domains --limit 20            # list app data domains
iosbackup-decrypt ls --domain AppDomain-com.example.app
iosbackup-decrypt find '*.sqlite'
iosbackup-decrypt extract --domain AppDomain-com.example.app --out ./dump
iosbackup-decrypt cat --domain AppDomain-com.example.app --path Documents/config.json
```

Password sources, in order: `--password`, `--password-file`, `$IOS_BACKUP_PASSWORD`, interactive prompt.

What it supports: iOS 10.2+ keybags (two-stage PBKDF2, `VERS=5` included), legacy unencrypted `Manifest.db` (iOS 10.0–10.2). Streams a 2.4 GB `Manifest.db` in ~4 s, caches the decrypted copy and builds a domain index; individual files are decrypted in streaming fashion.

Not supported: iCloud backups, and pre-iOS-10 `Manifest.mbdb` backups.

As a library:

```python
from iosbackup_crypto import Backup

with Backup("/path/to/MobileSync/Backup", password="secret") as bak:
    for rec in bak.iter_files(domain="AppDomain-com.example.app"):
        print(rec.relative_path, rec.size)
    data = bak.read_file("AppDomain-com.example.app", "Documents/notes.txt")
```

For **your own backups only**. MIT licensed.
