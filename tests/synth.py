# -*- coding: utf-8 -*-
"""Helpers that build a *synthetic* encrypted backup, so tests need no real data.

Everything here mirrors what iOS does:

* keybag TLV blob with a passcode-wrapped class key
* ``ManifestKey`` / ``EncryptionKey`` = class id (4B LE) + RFC 3394 wrapped key
* ``Manifest.db`` and file blobs = AES-256-CBC, zero IV, PKCS#7 padded
* ``Files.file`` = ``NSKeyedArchiver`` ``MBFile`` object
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import sqlite3
import struct

from Crypto.Cipher import AES

MAGIC = 0xA6A6A6A6A6A6A6A6


# --------------------------------------------------------------------------
# AES key wrap (RFC 3394), the inverse of iosbackup_crypto.keybag.aes_key_unwrap
# --------------------------------------------------------------------------
def aes_key_wrap(kek: bytes, plaintext: bytes) -> bytes:
    n = len(plaintext) // 8
    r = [struct.unpack(">Q", plaintext[i * 8:(i + 1) * 8])[0] for i in range(n)]
    a = MAGIC
    cipher = AES.new(kek, AES.MODE_ECB)
    for j in range(6):
        for i in range(n):
            block = cipher.encrypt(struct.pack(">Q", a) + struct.pack(">Q", r[i]))
            a = struct.unpack(">Q", block[:8])[0] ^ (n * j + i + 1)
            r[i] = struct.unpack(">Q", block[8:])[0]
    return struct.pack(">Q", a) + b"".join(struct.pack(">Q", value) for value in r)


# --------------------------------------------------------------------------
# TLV helpers
# --------------------------------------------------------------------------
def tlv(tag: bytes, value: bytes) -> bytes:
    return tag + struct.pack(">I", len(value)) + value


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def build_keybag(
    password: str,
    class_keys: dict,
    iterations: int = 500,
    double_protection: bool = True,
) -> bytes:
    """Build a TYPE=1 backup keybag whose class keys are wrapped with *password*."""
    salt = b"S" * 20
    dpsl = b"D" * 20
    dpic = 800

    if double_protection:
        secret = hashlib.pbkdf2_hmac("sha256", password.encode(), dpsl, dpic, 32)
    else:
        secret = password.encode()
    dek = hashlib.pbkdf2_hmac("sha1", secret, salt, iterations, 32)

    blob = b"".join([
        tlv(b"VERS", u32(5)),
        tlv(b"TYPE", u32(1)),
        tlv(b"UUID", b"U" * 16),
        tlv(b"HMCK", b"\x00" * 40),
        # VERS=5 stores a 4-byte flag here instead of a 40-byte wrapped key
        tlv(b"WRAP", u32(0)),
        tlv(b"SALT", salt),
        tlv(b"ITER", u32(iterations)),
        tlv(b"DPWT", u32(1)),
    ])
    if double_protection:
        blob += tlv(b"DPIC", u32(dpic)) + tlv(b"DPSL", dpsl)
    for class_id, key in sorted(class_keys.items()):
        blob += b"".join([
            tlv(b"UUID", b"K" * 16),
            tlv(b"CLAS", u32(class_id)),
            tlv(b"WRAP", u32(2)),          # 0x02 = wrapped with the passcode key
            tlv(b"KTYP", u32(0)),
            tlv(b"WPKY", aes_key_wrap(dek, key)),
        ])
    return blob


# --------------------------------------------------------------------------
# encryption helpers
# --------------------------------------------------------------------------
def encrypt_cbc(data: bytes, key: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    padded = data + bytes([pad]) * pad
    return AES.new(key, AES.MODE_CBC, b"\x00" * 16).encrypt(padded)


def mb_file_blob(relative_path: str, size: int, wrapped_file_key: bytes, class_id: int = 3) -> bytes:
    """An NSKeyedArchiver-encoded MBFile, the way Manifest.db stores it."""
    encryption_key = struct.pack("<i", class_id) + wrapped_file_key
    obj = {
        "Size": size,
        "EncryptionKey": encryption_key,
        "Flags": 0,
        "ProtectionClass": class_id,
        "LastModified": 1700000000,
        "RelativePath": relative_path,
        "$class": plistlib.UID(2),
    }
    archive = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {"root": plistlib.UID(1)},
        "$objects": [
            "$null",
            obj,
            {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
        ],
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


# --------------------------------------------------------------------------
# full synthetic backup
# --------------------------------------------------------------------------
def build_backup(
    root: str,
    password: str = "correct horse",
    udid: str = "00000000-0123456789ABCDEF",
    files=None,
) -> dict:
    """Create a minimal but structurally correct encrypted backup.

    *files* is ``{path: bytes}`` mapped to the ``AppDomain-com.example.app``
    domain. Returns a dict with the keys used by the tests.
    """
    if files is None:
        files = {
            "Documents/notes.txt": "hello 世界".encode("utf-8"),
            "Library/Preferences/com.example.plist": b"<?xml version='1.0'?><plist/>",
        }
    backup_dir = os.path.join(root, udid)
    os.makedirs(backup_dir, exist_ok=True)

    domain = "AppDomain-com.example.app"
    class_id = 3
    class_key = bytes(range(32))
    manifest_file_key = bytes(range(32, 64))
    dek = None

    rows = []
    for index, (path, content) in enumerate(sorted(files.items())):
        file_id = "%040x" % (index + 1)
        file_key = hashlib.sha256(b"file" + path.encode()).digest()
        wrapped = aes_key_wrap(class_key, file_key)
        blob = mb_file_blob(path, len(content), wrapped, class_id)
        encrypted = encrypt_cbc(content, file_key)
        os.makedirs(os.path.join(backup_dir, file_id[:2]), exist_ok=True)
        with open(os.path.join(backup_dir, file_id[:2], file_id), "wb") as handle:
            handle.write(encrypted)
        rows.append((file_id, domain, path, 0, blob))

    # Manifest.db
    db_path = os.path.join(root, "plain-manifest.db")
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, "
        "flags INTEGER, file BLOB)"
    )
    con.executemany("INSERT INTO Files VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()
    with open(db_path, "rb") as handle:
        manifest_db = handle.read()
    with open(os.path.join(backup_dir, "Manifest.db"), "wb") as handle:
        handle.write(encrypt_cbc(manifest_db, manifest_file_key))

    keybag = build_keybag(password, {class_id: class_key})
    manifest_key = struct.pack("<i", class_id) + aes_key_wrap(class_key, manifest_file_key)
    manifest = {
        "IsEncrypted": True,
        "WasPasscodeSet": True,
        "Version": "10.0",
        "SystemDomainsVersion": "24.0",
        "ManifestKey": manifest_key,
        "BackupKeyBag": keybag,
        "Lockdown": {
            "DeviceName": "Test iPhone",
            "ProductType": "iPhone15,2",
            "ProductVersion": "17.4",
            "BuildVersion": "21E219",
            "SerialNumber": "TESTSERIAL",
        },
        "Date": __import__("datetime").datetime(2024, 1, 2, 3, 4, 5),
    }
    with open(os.path.join(backup_dir, "Manifest.plist"), "wb") as handle:
        plistlib.dump(manifest, handle, fmt=plistlib.FMT_BINARY)

    os.remove(db_path)
    return {
        "backup_dir": backup_dir,
        "root": root,
        "udid": udid,
        "domain": domain,
        "files": files,
        "password": password,
        "class_key": class_key,
        "manifest_file_key": manifest_file_key,
    }
