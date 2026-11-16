# iosbackup-decrypt

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![tests](https://github.com/WhiteAshura/ios-backup-decryptor/actions/workflows/tests.yml/badge.svg)](https://github.com/WhiteAshura/ios-backup-decryptor/actions/workflows/tests.yml)

纯 Python 的 iOS 加密备份解密工具。不越狱，不装外部二进制，也不连手机，只要备份文件夹和它的密码。

它做两件事：把加密的 `Manifest.db` 解出来，然后按清单解密备份里的任意一个文件。

```bash
pip install iosbackup-decrypt

iosbackup-decrypt info                      # 设备信息，顺便验证密码
iosbackup-decrypt domains --limit 20        # 有哪些 App 的数据
iosbackup-decrypt ls --domain AppDomain-com.example.app
iosbackup-decrypt extract --domain AppDomain-com.example.app --out ./dump
```

---

## 能做什么

支持 iOS 10.2 以后的所有加密备份，包括 `VERS=5` 的新 keybag；iOS 10.0–10.2 那种未加密的 `Manifest.db` 也能读。

备份多大都行。2.4 GB 的 `Manifest.db` 流式解出来大约 4 秒，解出的副本按（大小, mtime）做指纹缓存，同时建一个 domain 索引，之后按 App 查文件基本不花时间。单个文件也是流式解密，700 MB 的视频不会一口气读进内存。

命令行够用，也可以当库调：`from iosbackup_crypto import Backup`。

文件在备份里被截断、或者缺 class key，它会报出来，不会假装成功。

## 安装

```bash
# 从源码（能看清它到底做了什么）
git clone https://github.com/WhiteAshura/ios-backup-decryptor.git
cd ios-backup-decryptor
pip install -e .

# 或者只要依赖、不装包
pip install pycryptodome
PYTHONPATH=src python -m iosbackup_crypto info
```

需要 Python 3.9 以上。

## 快速开始

先找到备份目录。

| 平台 | 位置 |
|---|---|
| Windows | `%APPDATA%\Apple Computer\MobileSync\Backup` |
| macOS | `~/Library/Application Support/MobileSync/Backup` |
| iMazing（自定义位置） | 例如 `~/Apple/MobileSync/Backup` |

里面通常是 `<UDID>` 文件夹，`Manifest.plist` 就在里面。工具既能接受父目录（自动找 UDID），也能直接给 UDID 目录。

```bash
# 1) 设备和备份信息。这一步就把密码验证了
iosbackup-decrypt info
```

```
backup        C:\Users\me\AppData\Roaming\Apple Computer\MobileSync\Backup\<UDID>
device        iPhone
model         iPhone15,2
ios           17.4 (21E219)
udid          <UDID>
last backup   2026-11-14 15:41:28
encrypted     yes
passcode set  yes
Manifest.db   2.4 GB
keybag        v5 / TYPE=1
pbkdf2        10,000 + 10,000,000 (SHA-256 stage)
classes       1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 17, 18, 19
```

```bash
# 2) 看有哪些数据域。App 容器就是 AppDomain-<bundle id>
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
# 3) 列某个 App 里的文件
iosbackup-decrypt ls --domain AppDomain-com.example.app
iosbackup-decrypt ls --domain AppDomain-com.example.app --path Documents --glob '*.sqlite'
```

```bash
# 4) 导出整个 App 容器，保留 Documents/... 的目录结构
iosbackup-decrypt extract --domain AppDomain-com.example.app --out ./dump

# 只导某类文件，跳过超大文件
iosbackup-decrypt extract --domain AppDomain-com.example.app --glob '*.sqlite' --max-size 50 --out ./dump
```

```bash
# 5) 全库搜文件，按路径或文件名匹配
iosbackup-decrypt find '*.sqlite' --limit 20
iosbackup-decrypt find 'Library/Preferences/*' --domain AppDomain-com.example.app
```

```bash
# 6) 打印一个小文件，或者另存
iosbackup-decrypt cat --domain AppDomain-com.example.app --path Documents/config.json
iosbackup-decrypt cat --domain AppDomain-com.example.app --path Library/Preferences/x.plist -o x.plist
```

密码有四种给法，优先级从高到低：

```bash
iosbackup-decrypt --password 'secret' info              # 会警告，进程列表可见
iosbackup-decrypt --password-file ~/.iosbak.pw info
IOS_BACKUP_PASSWORD='secret' iosbackup-decrypt info     # 推荐
iosbackup-decrypt info                                  # 都没有就交互输入
```

## 命令参考

| 命令 | 作用 |
|---|---|
| `info` | 设备/备份元信息，顺便验证密码。加 `--count` 会统计文件总数（慢） |
| `domains` | 列出数据域和文件数，按数量降序 |
| `ls --domain X` | 列出该域的条目（大小、修改时间、路径），可加 `--path` / `--glob` |
| `find GLOB` | 按路径或文件名匹配，跨域搜索 |
| `extract` | 解密落盘，默认保留 `domain/relativePath` 结构，`--flatten` 拍平 |
| `cat` | 打印单个文件，`-o` 存成文件 |
| `check` | 只验证密码，不解大文件 |
| `clean` | 删掉缓存的解密副本 |

通用参数：`-b/--backup`、`--password`、`--password-file`、`--no-cache`、`--cache-dir`、`-v`、`--json`。

`extract` 在没给 `--domain` / `--path` / `--glob` 时会拒绝执行，免得手一抖导出上百万个文件。

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

常用的成员：

| 成员 | 说明 |
|---|---|
| `bak.info(count_files=False)` | 设备/备份信息 dict |
| `bak.domains()` | `{domain: 文件数}` |
| `bak.iter_files(domain=, glob=, path_prefix=)` | 迭代 `FileRecord` |
| `bak.get_file(domain, path)` | 取单条 `FileRecord` |
| `bak.read_file(domain, path)` | 解密成 `bytes` |
| `bak.extract_file(record, target)` | 流式解密到磁盘，返回字节数 |
| `bak.extract(records, out_dir, flatten=False, max_size=None)` | 批量导出 |
| `bak.clear_cache()` | 清掉缓存的 `Manifest.db` |

## 它是怎么工作的

### 备份的结构

```
Backup/<UDID>/
├── Manifest.plist      # keybag + ManifestKey + 设备信息（永远不加密）
├── Manifest.db         # 文件清单，SQLite；现代 iOS 上整库加密
├── Status.plist
├── 00/ 01/ … ff/       # 文件内容，按 fileID 前两位十六进制分桶
│   └── <fileID>        # AES-256-CBC（零 IV）密文
```

`Manifest.db` 的 `Files` 表每行是 `fileID / domain / relativePath / flags / file`。其中 `file` 是一个 `NSKeyedArchiver` 编码的 `MBFile` 对象，里面装着 `Size` 和 `EncryptionKey`。

### 两层密钥

第一层从密码派生出类密钥。

`Manifest.plist` 里的 `BackupKeyBag` 是一串 TLV 记录（tag 4 字节 ASCII + 长度 4 字节大端 + 值）：

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

然后对每个 `WRAP & 0x02`（由密码保护）的类，用 `dek` 做 RFC 3394 的 AES 密钥解包，得到该类密钥。密码错了会在这一步的完整性校验上失败。

第二层从类密钥走到文件密钥，再到明文。

```
ManifestKey        = 类编号(4 字节小端) || AES-KW(类密钥, Manifest.db 的密钥)
EncryptionKey      = 类编号(4 字节小端) || AES-KW(类密钥, 该文件的密钥)
明文               = AES-256-CBC 解密(密文, 文件密钥, IV=全 0)[:Size]
```

`Manifest.db` 解开之后就是一个普通 SQLite。单个文件按 `Size` 截断，只有 `Size` 缺失时才去剥 PKCS#7 padding。

### 实现时踩到的地方

`VERS=5` 的 keybag 头部那个 `WRAP` 字段是 4 字节标志位，不是 40 字节被包裹的密钥，不能拿它做密码校验。

类密钥的 `WRAP` 标志位要分清：`0x01` 是用设备 UID 包裹的，备份里根本解不开，要跳过；只有 `0x02` 才是密码保护。

`Manifest.db` 尾部有填充。用 SQLite 头里的 page size 乘 page count 精确截断，比盲剥 PKCS#7 稳得多。

`file` 列见过两种编码：现代的是 `NSKeyedArchiver`（带 `$objects`），很老的是普通 plist dict，两种都得认。

还有一种情况是 `Size` 比实际密文长度大，说明备份时文件被截断了。这类只能解出可读前缀，工具会告警。

## 常见问题

**忘了备份密码怎么办？**
没办法。AES-KW 的完整性校验加上 10,000,000 次 PBKDF2 就是防这个的。只能重新做一份不加密的备份。

**iCloud 备份能用吗？**
不能。iCloud 备份不在本地磁盘上，keybag 也不一样，得先下载到本地，而 iOS 不允许直接导出。

**这是越狱工具吗？要连手机吗？**
都不是。它只读你磁盘上已有的那个备份文件夹。

**能拿到 App 的 `Library/Caches` 吗？**
备份里没有就没有。iOS 做备份时默认排除这个目录，所以微信语音、抖音聊天图片这类缓存媒体从备份里取不到。工具只能给你备份里真实存在的东西。

**iOS 10 以前的备份（`Manifest.mbdb`）支持吗？**
不支持，会明确报错。那种格式的加密方式不一样，得用 [iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection) 那类老工具。

**第一次跑 `domains` 为什么要几秒？**
要先把 2.4 GB 的 `Manifest.db` 解一遍并建索引。之后走缓存就是毫秒级。缓存位置在 `%LOCALAPPDATA%\iosbackup-decrypt\<UDID>\`（macOS 和 Linux 在 `~/.cache/iosbackup-decrypt/`），用 `clean` 删掉，或者全程加 `--no-cache` 不用磁盘缓存。

**和别的工具比呢？**
格式都是社区逆向出来的，思路同源。可以看 [iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection)（C 和 Python）、[iOSbackup](https://pypi.org/project/iOSbackup/)（纯 Python 库）、[iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt)。这个项目的重点是在命令行的可用性：不写代码就能 `ls` / `find` / `extract`，另外带了缓存、索引、流式解密和截断告警。

## 安全

密码优先用 `--password-file` 或 `$IOS_BACKUP_PASSWORD`。`--password` 会出现在进程列表里，工具会警告。密码不做任何持久化。

缓存里的 `Manifest.db` 解密副本是明文的，不然每次都得重解。用完记得 `iosbackup-decrypt clean`，或者全程 `--no-cache`。

`extract` 出来的都是明文，里面可能有通讯录、聊天库、Token 这类东西，放哪儿自己注意。

工具不联网，不上传任何数据。

## 开发

```bash
pip install -e '.[dev]'
pytest        # 26 个测试，全部用合成备份，不需要真实数据
```

测试会现场造一个结构正确的加密备份，keybag、`Manifest.db`、文件密文都用真实格式，所以在 CI 里也能跑。

想拿真实备份做冒烟测试（需要你自己的密码）：

```bash
export IOS_BACKUP_PASSWORD='...'
python tools/real_backup_smoke.py "/path/to/MobileSync/Backup" AppDomain-com.tencent.xin
```

## 免责声明

只用来恢复你自己设备、你自己备份里的数据。用别人的设备、或者未经授权拿到的数据，可能违法。作者不承担滥用带来的任何责任。

## License

MIT，见 [LICENSE](LICENSE)。

---

## English

Pure-Python decryptor for **encrypted iOS backups**. No jailbreak, no external binaries, no device — just the backup folder and its password.

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

Works with iOS 10.2+ keybags (two-stage PBKDF2, `VERS=5` included) and the legacy unencrypted `Manifest.db` from iOS 10.0–10.2. A 2.4 GB `Manifest.db` streams in about 4 seconds; the decrypted copy is cached and indexed so per-app lookups are instant. Individual files are decrypted streaming, so large videos never land in memory.

Not supported: iCloud backups, and pre-iOS-10 `Manifest.mbdb` backups.

As a library:

```python
from iosbackup_crypto import Backup

with Backup("/path/to/MobileSync/Backup", password="secret") as bak:
    for rec in bak.iter_files(domain="AppDomain-com.example.app"):
        print(rec.relative_path, rec.size)
    data = bak.read_file("AppDomain-com.example.app", "Documents/notes.txt")
```

MIT licensed. For **your own backups only**.
