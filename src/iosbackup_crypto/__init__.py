# -*- coding: utf-8 -*-
"""iosbackup-decrypt — decrypt and browse encrypted iOS/iPadOS backups.

Pure Python, no external binaries. Works with backups made by Finder, iTunes or
iMazing, as long as you know the backup password.

Public API
----------
    from iosbackup_crypto import Backup

    bak = Backup("C:/Users/me/AppData/Roaming/Apple Computer/MobileSync/Backup",
                 password="secret")
    bak.info()                        # dict of device/backup metadata
    bak.domains()                     # {domain: file_count}
    for rec in bak.iter_files(domain="AppDomain-com.example.app"):
        print(rec.relative_path, rec.size)
    data = bak.read_file(domain="AppDomain-com.example.app",
                         relative_path="Documents/notes.sqlite")
"""

from .keybag import Keybag, KeybagError, aes_key_unwrap
from .manifest import Backup, BackupError, FileRecord, ManifestError

__version__ = "0.1.0"
__all__ = [
    "Backup",
    "FileRecord",
    "Keybag",
    "KeybagError",
    "BackupError",
    "ManifestError",
    "aes_key_unwrap",
    "__version__",
]
