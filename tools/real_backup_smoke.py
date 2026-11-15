# -*- coding: utf-8 -*-
"""End-to-end smoke test against a real backup (run manually, not part of pytest).

Usage:
    set IOS_BACKUP_PASSWORD=...
    python tools/real_backup_smoke.py "C:/path/to/MobileSync/Backup" AppDomain-com.example.app
"""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from iosbackup_crypto.manifest import Backup  # noqa: E402


def main() -> int:
    backup_path = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else "AppDomain-com.ss.iphone.ugc.Aweme"
    password = os.environ.get("IOS_BACKUP_PASSWORD")

    with tempfile.TemporaryDirectory() as tmp:
        with Backup(backup_path, password=password, cache_dir=tmp, verbose=True) as bak:
            info = bak.info()
            print("device:", info["device_name"], info["product_type"], info["ios_version"])
            print("domains:", len(bak.domains()))

            entries = list(bak.iter_files(domain=domain))
            print("%s: %d entries" % (domain, len(entries)))

            sqlite_files = [r for r in entries if r.relative_path.endswith(".sqlite") and r.size]
            print("sqlite files:", len(sqlite_files))

            sqlite_files.sort(key=lambda r: -r.size)
            sample = sqlite_files[0]
            target = os.path.join(tmp, "sample.sqlite")
            written = bak.extract_file(sample, target)
            print("extracted:", sample.relative_path, written, "bytes")

            con = sqlite3.connect(target)
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            print("tables in sample:", tables[:6], "...")
            con.close()

            blob_size = os.path.getsize(os.path.join(bak.path, sample.blob_path))
            expected = min(sample.size, blob_size) if sample.size else written
            print("declared size:", sample.size, "blob size:", blob_size)
            assert written == expected, "size mismatch: %d != %d" % (written, expected)
            assert os.path.getsize(target) == expected
            if sample.size and blob_size < sample.size:
                print("note: this blob is truncated in the backup (expected, handled)")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
