# -*- coding: utf-8 -*-
"""Read an iOS backup: decrypt ``Manifest.db`` and any file inside the backup.

Layout of an encrypted backup::

    Backup/
      <UDID>/
        Manifest.plist      # keybag, ManifestKey, device info (never encrypted)
        Manifest.db         # file catalog; encrypted on modern iOS
        Info.plist          # installed apps (XML plist, never encrypted)
        Status.plist
        00/ 01/ ... ff/     # file content, named by the first 2 hex chars of fileID
          <fileID>          # AES-256-CBC (zero IV) encrypted content

Each row of ``Manifest.db.Files`` has ``fileID`` / ``domain`` /
``relativePath`` / ``flags`` / ``file``, where ``file`` is an
``NSKeyedArchiver`` plist holding ``Size``, ``EncryptionKey`` and friends.
``EncryptionKey`` is ``class_id(4, little endian) || wrapped_key(40)``; the
per-file AES key is the RFC 3394 unwrap of ``wrapped_key`` with that class key,
and the blob is AES-256-CBC decrypted with an all-zero IV.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from Crypto.Cipher import AES

from .keybag import Keybag, KeybagError, aes_key_unwrap

CHUNK = 8 * 1024 * 1024
SQLITE_MAGIC = b"SQLite format 3\x00"


class BackupError(Exception):
    """Generic backup access error."""


class ManifestError(BackupError):
    """The backup catalog is missing or unsupported."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _strip_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding if it is present and valid."""
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and len(data) >= pad and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def _finalize_sqlite(path: str) -> None:
    """Trim block padding so SQLite sees an exact-size database file."""
    size = os.path.getsize(path)
    if size < 100:
        return
    with open(path, "r+b") as handle:
        header = handle.read(100)
        if header[:16] == SQLITE_MAGIC:
            page_size = struct.unpack(">H", header[16:18])[0]
            if page_size == 1:
                page_size = 65536
            page_count = struct.unpack(">I", header[28:32])[0]
            expected = page_size * page_count
            if page_count and page_size and 0 < expected <= size:
                handle.truncate(expected)
                return
        # fall back to PKCS#7 detection
        seek_to = max(0, size - 16)
        handle.seek(seek_to)
        tail = handle.read()
        stripped = _strip_pkcs7(tail)
        if len(stripped) != len(tail):
            handle.truncate(seek_to + len(stripped))


def _decode_mb_file(blob: Optional[bytes]) -> Dict:
    """Decode one ``Files.file`` value into a plain dict.

    Modern backups encode an ``MBFile`` object with ``NSKeyedArchiver``; very
    old ones store a plain plist dictionary instead. Both are handled.
    """
    if not blob:
        return {}
    try:
        parsed = plistlib.loads(blob)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    if "$objects" not in parsed:  # legacy plain dictionary
        return {str(k): v for k, v in parsed.items()}

    objects = parsed["$objects"]

    def deref(value):
        hops = 0
        while isinstance(value, plistlib.UID):
            value = objects[value.data]
            hops += 1
            if hops > 8:  # defensive: avoid pathological reference chains
                break
        if isinstance(value, dict) and "NS.data" in value:
            return value["NS.data"]
        return value

    top = parsed.get("$top") or {}
    root = deref(top.get("root"))
    if not isinstance(root, dict):
        return {}
    return {str(k): deref(v) for k, v in root.items() if not str(k).startswith("$")}


def default_cache_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "iosbackup-decrypt")


def find_backups(root: str) -> List[str]:
    """Return every backup directory below *root* (or *root* itself)."""
    root = os.path.abspath(os.path.expanduser(root))
    if os.path.isfile(os.path.join(root, "Manifest.plist")):
        return [root]
    found: List[str] = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            candidate = os.path.join(root, name)
            if os.path.isfile(os.path.join(candidate, "Manifest.plist")):
                found.append(candidate)
    return found


def default_backup_roots() -> List[str]:
    """Well-known backup locations on this machine."""
    home = os.path.expanduser("~")
    if os.name == "nt":
        appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return [
            os.path.join(appdata, "Apple Computer", "MobileSync", "Backup"),
            os.path.join(home, "Apple", "MobileSync", "Backup"),
        ]
    return [
        os.path.join(home, "Library", "Application Support", "MobileSync", "Backup"),
        os.path.join(home, "Apple", "MobileSync", "Backup"),
    ]


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------
class FileRecord:
    """One file (or directory) as recorded in ``Manifest.db``."""

    __slots__ = (
        "file_id", "domain", "relative_path", "size", "flags",
        "protection_class", "encryption_key", "modified", "birth", "mode",
    )

    def __init__(self, file_id: str, domain: str, relative_path: str, meta: Dict) -> None:
        self.file_id = file_id
        self.domain = domain
        self.relative_path = relative_path
        self.size = int(meta.get("Size") or 0)
        self.flags = int(meta.get("Flags") or 0)
        self.protection_class = meta.get("ProtectionClass")
        self.encryption_key = meta.get("EncryptionKey")
        self.modified = meta.get("LastModified")
        self.birth = meta.get("Birth")
        self.mode = meta.get("Mode")

    @property
    def is_directory(self) -> bool:
        return not self.encryption_key

    @property
    def blob_path(self) -> str:
        """Relative location of the encrypted blob inside the backup."""
        return os.path.join(self.file_id[:2], self.file_id)

    def as_dict(self) -> Dict:
        return {
            "fileID": self.file_id,
            "domain": self.domain,
            "relativePath": self.relative_path,
            "size": self.size,
            "isDirectory": self.is_directory,
            "protectionClass": self.protection_class,
            "modified": self.modified,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        kind = "dir" if self.is_directory else "file"
        return f"<FileRecord {kind} {self.domain}:{self.relative_path} {self.size}B>"


# --------------------------------------------------------------------------
# main class
# --------------------------------------------------------------------------
class Backup:
    """An iOS backup directory, optionally password protected."""

    def __init__(
        self,
        path: str,
        password: Optional[str] = None,
        cache_dir: Optional[str] = None,
        use_cache: bool = True,
        verbose: bool = False,
        quiet_warnings: bool = False,
    ) -> None:
        candidates = find_backups(path)
        if not candidates:
            raise BackupError(
                "no iOS backup found at %r (expected a folder containing Manifest.plist)" % path
            )
        if len(candidates) > 1:
            raise BackupError(
                "several backups found under %r, pass the UDID folder explicitly:\n  %s"
                % (path, "\n  ".join(candidates))
            )
        self.path = candidates[0]
        self.udid = os.path.basename(self.path)
        self.verbose = verbose
        self.quiet_warnings = quiet_warnings
        self.use_cache = use_cache
        self.cache_dir = cache_dir or default_cache_dir()

        self.manifest: Dict = {}
        self.keybag: Optional[Keybag] = None
        self.encrypted = False
        self.class_keys: Dict[int, bytes] = {}
        self._manifest_db: Optional[str] = None
        self._owns_decrypted_copy = False
        self._conn: Optional[sqlite3.Connection] = None

        self._load_manifest(password)

    # -- logging ---------------------------------------------------------
    def _log(self, message: str) -> None:
        if self.verbose:
            print("[iosbackup] %s" % message)

    def _warn(self, message: str) -> None:
        if not self.quiet_warnings:
            print("[iosbackup] warning: %s" % message, file=sys.stderr)

    # -- manifest / keys -------------------------------------------------
    def _load_manifest(self, password: Optional[str]) -> None:
        with open(os.path.join(self.path, "Manifest.plist"), "rb") as handle:
            self.manifest = plistlib.load(handle)

        self.encrypted = bool(self.manifest.get("IsEncrypted"))
        keybag_blob = self.manifest.get("BackupKeyBag")
        if keybag_blob:
            self.keybag = Keybag.from_bytes(keybag_blob)

        if not self.encrypted:
            self._log("backup is not encrypted; no password required")
            return

        if password is None:
            raise BackupError("backup is encrypted: a password is required")
        if self.keybag is None:
            raise BackupError("encrypted backup without a BackupKeyBag in Manifest.plist")
        try:
            self.class_keys = self.keybag.unlock(password)
        except KeybagError as exc:
            raise BackupError(str(exc)) from exc
        self._log("unlocked %d protection classes" % len(self.class_keys))

    # -- manifest.db -----------------------------------------------------
    @property
    def manifest_db_size(self) -> int:
        try:
            return os.path.getsize(os.path.join(self.path, "Manifest.db"))
        except OSError:
            return 0

    def _cache_paths(self) -> Tuple[str, str]:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.udid)
        base = os.path.join(self.cache_dir, safe)
        return base, os.path.join(base, "Manifest.dec.db")

    def _cache_is_fresh(self, fingerprint_path: str, source: str) -> bool:
        try:
            with open(fingerprint_path, "r", encoding="utf-8") as handle:
                stamp = json.load(handle)
            stat = os.stat(source)
        except (OSError, ValueError):
            return False
        return stamp.get("size") == stat.st_size and stamp.get("mtime_ns") == stat.st_mtime_ns

    def manifest_db(self) -> str:
        """Path to a readable (decrypted) copy of ``Manifest.db``."""
        if self._manifest_db:
            return self._manifest_db

        source = os.path.join(self.path, "Manifest.db")
        if not os.path.isfile(source):
            if os.path.isfile(os.path.join(self.path, "Manifest.mbdb")):
                raise ManifestError(
                    "this is a legacy (iOS < 10) backup that uses Manifest.mbdb, which is not supported"
                )
            raise ManifestError("Manifest.db is missing from %s" % self.path)

        with open(source, "rb") as handle:
            head = handle.read(16)
        if head == SQLITE_MAGIC or not self.encrypted:
            # Unencrypted catalog: read it in place, never modified.
            self._manifest_db = source
            return source

        manifest_key = self.manifest.get("ManifestKey")
        if not manifest_key or len(manifest_key) < 44:
            raise ManifestError("encrypted backup without a usable ManifestKey")

        class_id = struct.unpack("<i", manifest_key[:4])[0]
        class_key = self.class_keys.get(class_id)
        if class_key is None:
            raise ManifestError(
                "no unwrapped key for the Manifest.db protection class %d" % class_id
            )
        file_key = aes_key_unwrap(class_key, manifest_key[4:])

        base, cached = self._cache_paths()
        fingerprint = cached + ".json"
        if self.use_cache and os.path.isfile(cached) and self._cache_is_fresh(fingerprint, source):
            self._log("reusing cached Manifest.db")
            self._manifest_db = cached
            self._owns_decrypted_copy = True
            return cached

        if self.use_cache:
            os.makedirs(base, exist_ok=True)
            target = cached
        else:
            handle = tempfile.NamedTemporaryFile(
                prefix="iosbackup-Manifest-", suffix=".dec.db", delete=False
            )
            handle.close()
            target = handle.name

        self._log("decrypting Manifest.db (%.1f MB) ..." % (self.manifest_db_size / 1048576))
        self._decrypt_manifest_db(source, target, file_key)
        self._owns_decrypted_copy = True

        if self.use_cache:
            try:
                stat = os.stat(source)
                with open(fingerprint, "w", encoding="utf-8") as handle:
                    json.dump({"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}, handle)
            except OSError:
                pass
        self._manifest_db = target
        return target

    def _decrypt_manifest_db(self, source: str, target: str, key: bytes) -> None:
        cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)  # stateful: chains per chunk
        temp_target = target + ".part"
        with open(source, "rb") as src, open(temp_target, "wb") as dst:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                if len(chunk) % 16:
                    chunk = chunk[: len(chunk) // 16 * 16]
                    if not chunk:
                        break
                dst.write(cipher.decrypt(chunk))
        _finalize_sqlite(temp_target)
        os.replace(temp_target, target)

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            uri = "file:%s?mode=ro" % self.manifest_db().replace("\\", "/")
            self._conn = sqlite3.connect(uri, uri=True)
        return self._conn

    def _ensure_index(self) -> None:
        """Create a domain index in our own decrypted copy, once."""
        if not (self.use_cache and self._owns_decrypted_copy):
            return
        try:
            writable = sqlite3.connect(self.manifest_db())
            try:
                names = {row[1] for row in writable.execute("PRAGMA index_list('Files')")}
                if "idx_files_domain" in names:
                    return
                writable.execute(
                    "CREATE INDEX IF NOT EXISTS idx_files_domain ON Files(domain, relativePath)"
                )
                writable.commit()
                self._log("built domain index for faster lookups")
            finally:
                writable.close()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Backup":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- metadata --------------------------------------------------------
    def info(self, count_files: bool = False) -> Dict:
        lockdown = self.manifest.get("Lockdown") or {}
        date = self.manifest.get("Date")
        backup_date = (
            date.strftime("%Y-%m-%d %H:%M:%S") if isinstance(date, _dt.datetime) else str(date)
        )
        result = {
            "backup_path": self.path,
            "udid": self.udid,
            "device_name": lockdown.get("DeviceName"),
            "product_type": lockdown.get("ProductType"),
            "ios_version": lockdown.get("ProductVersion"),
            "build_version": lockdown.get("BuildVersion"),
            "serial_number": lockdown.get("SerialNumber"),
            "last_backup": backup_date,
            "encrypted": self.encrypted,
            "passcode_set": bool(self.manifest.get("WasPasscodeSet")),
            "keybag_version": self.keybag.version if self.keybag else None,
            "keybag_type": self.keybag.type if self.keybag else None,
            "pbkdf2_iterations": self.keybag.iterations if self.keybag else None,
            "pbkdf2_double_iterations": (
                self.keybag.double_protection_iterations
                if self.keybag and self.keybag.has_double_protection
                else None
            ),
            "manifest_db_size": self.manifest_db_size,
            "unlocked_classes": sorted(self.class_keys),
        }
        if count_files:
            result["file_count"] = self._connection().execute(
                "SELECT COUNT(*) FROM Files"
            ).fetchone()[0]
        return result

    def domains(self) -> Dict[str, int]:
        """``{domain: number_of_files}``, most populated first."""
        self._ensure_index()
        rows = self._connection().execute(
            "SELECT domain, COUNT(*) AS n FROM Files GROUP BY domain ORDER BY n DESC, domain"
        ).fetchall()
        return {domain: int(count) for domain, count in rows}

    # -- querying --------------------------------------------------------
    def iter_files(
        self,
        domain: Optional[str] = None,
        glob: Optional[str] = None,
        path_prefix: Optional[str] = None,
    ) -> Iterator[FileRecord]:
        """Iterate catalog entries, optionally filtered.

        *glob* is shell-style and matched against the relative path
        (``*.sqlite``, ``Library/Preferences/*``, ...).
        """
        self._ensure_index()
        sql = "SELECT fileID, domain, relativePath, file FROM Files"
        params: Tuple = ()
        conditions = []
        if domain:
            conditions.append("domain = ?")
            params += (domain,)
        if path_prefix:
            conditions.append("relativePath LIKE ?")
            params += (path_prefix.replace("\\", "/") + "%",)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY domain, relativePath"

        # A pattern matches either the whole relative path or just the file name,
        # so both 'Documents/*.plist' and '*.plist' (and 'com.example.plist') work.
        full_re = re.compile(fnmatch.translate(glob)) if glob else None
        base_re = re.compile(fnmatch.translate(glob)) if glob else None
        for file_id, dom, rel, blob in self._connection().execute(sql, params):
            if full_re and not (full_re.match(rel) or base_re.match(rel.rsplit("/", 1)[-1])):
                continue
            yield FileRecord(file_id, dom, rel, _decode_mb_file(blob))

    def get_file(self, domain: str, relative_path: str) -> Optional[FileRecord]:
        row = self._connection().execute(
            "SELECT fileID, domain, relativePath, file FROM Files "
            "WHERE domain = ? AND relativePath = ?",
            (domain, relative_path.replace("\\", "/")),
        ).fetchone()
        if not row:
            return None
        return FileRecord(row[0], row[1], row[2], _decode_mb_file(row[3]))

    # -- decryption ------------------------------------------------------
    def file_key(self, record: FileRecord) -> bytes:
        """Unwrap the per-file AES key of a record."""
        if record.is_directory:
            raise BackupError("%s is a directory" % record.relative_path)
        raw = record.encryption_key
        if len(raw) < 44:
            raise BackupError("truncated EncryptionKey for %s" % record.relative_path)
        class_id = struct.unpack("<i", raw[:4])[0]
        class_key = self.class_keys.get(class_id)
        if class_key is None:
            raise BackupError(
                "file needs protection class %d, which this keybag did not unlock" % class_id
            )
        return aes_key_unwrap(class_key, raw[4:])

    def iter_decrypted(self, record: FileRecord, chunk: int = CHUNK) -> Iterator[bytes]:
        """Yield decrypted plaintext chunks of a file record."""
        key = self.file_key(record)
        cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        remaining = record.size or None
        with open(os.path.join(self.path, record.blob_path), "rb") as src:
            while True:
                want = chunk
                if remaining is not None:
                    want = min(chunk, ((remaining + 15) // 16) * 16)
                    if want <= 0:
                        break
                block = src.read(want)
                if not block:
                    break
                if len(block) % 16:
                    block = block[: len(block) // 16 * 16]
                    if not block:
                        break
                plain = cipher.decrypt(block)
                if remaining is not None:
                    plain = plain[:remaining]
                    remaining -= len(plain)
                yield plain
                if remaining is not None and remaining <= 0:
                    break

    def read_file(self, domain: str, relative_path: str) -> bytes:
        """Return the decrypted content of a single file."""
        record = self.get_file(domain, relative_path)
        if record is None:
            raise BackupError("not found: %s:%s" % (domain, relative_path))
        data = b"".join(self.iter_decrypted(record))
        if record.size and len(data) < record.size:
            self._warn(
                "%s: got %d of %d bytes (the blob in this backup is truncated)"
                % (record.relative_path, len(data), record.size)
            )
        return data if record.size else _strip_pkcs7(data)

    def extract_file(self, record: FileRecord, target_path: str) -> int:
        """Decrypt one record to *target_path*; returns the byte count."""
        parent = os.path.dirname(target_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        written = 0
        with open(target_path, "wb") as dst:
            for chunk in self.iter_decrypted(record):
                dst.write(chunk)
                written += len(chunk)
        if not record.size:  # unknown size: drop PKCS#7 padding
            with open(target_path, "rb") as handle:
                data = handle.read()
            stripped = _strip_pkcs7(data)
            if len(stripped) != len(data):
                with open(target_path, "wb") as handle:
                    handle.write(stripped)
                written = len(stripped)
        elif written < record.size:
            # A few files are recorded larger than their blob (interrupted backup,
            # or partially uploaded data). The readable prefix is still useful.
            self._warn(
                "%s: got %d of %d bytes (truncated blob, extracted the readable part)"
                % (record.relative_path, written, record.size)
            )
        if record.modified:
            try:
                stamp = float(record.modified)
                os.utime(target_path, (stamp, stamp))
            except (OSError, ValueError, TypeError):
                pass
        return written

    def extract(
        self,
        records: Iterable[FileRecord],
        out_dir: str,
        flatten: bool = False,
        max_size: Optional[int] = None,
    ) -> List[str]:
        """Extract records below *out_dir*, keeping ``domain/relativePath``."""
        written: List[str] = []
        for record in records:
            if record.is_directory:
                continue
            if max_size is not None and record.size > max_size:
                self._log("skipping %s (too large: %d bytes)" % (record.relative_path, record.size))
                continue
            if flatten:
                target = os.path.join(out_dir, record.relative_path.replace("/", "__"))
            else:
                target = os.path.join(
                    out_dir, record.domain, record.relative_path.replace("/", os.sep)
                )
            self.extract_file(record, target)
            written.append(target)
        return written

    # -- maintenance -----------------------------------------------------
    def clear_cache(self) -> None:
        base, _ = self._cache_paths()
        if os.path.isdir(base):
            shutil.rmtree(base, ignore_errors=True)
