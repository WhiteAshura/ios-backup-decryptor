# -*- coding: utf-8 -*-
"""iOS backup keybag parsing and key unwrapping.

Background
----------
An encrypted iOS backup stores its keys in ``Manifest.plist`` under
``BackupKeyBag``. The keybag is a sequence of TLV records::

    +--------+-------------+------------------+
    | tag(4) | length(4B)  | value(length B)  |   tag is ASCII, length big-endian
    +--------+-------------+------------------+

Header fields (payload of a TYPE=1 "backup" keybag)::

    VERS  uint32   keybag version (4 or 5)
    TYPE  uint32   1 = backup keybag, 0 = device keybag
    UUID  16 bytes unique keybag id
    HMCK  40 bytes wrapped HMAC key (not needed for backups)
    WRAP  40 bytes wrapped key-encryption key
    SALT  20 bytes PBKDF2 salt
    ITER  uint32   PBKDF2 iteration count
    DPWT  uint32   key derivation work factor (unused for backups)
    DPIC  uint32   second-stage PBKDF2 iteration count (iOS >= 10.2)
    DPSL  20 bytes second-stage PBKDF2 salt (iOS >= 10.2)

Followed by one record per protection class::

    UUID  16 bytes
    CLAS  uint32   protection class (1..11, 17..19)
    WRAP  uint32   wrapping flags: 0x01 = device key, 0x02 = passcode key
    KTYP  uint32   key type
    WPKY  40 bytes wrapped per-class key (AES-256 key wrap, RFC 3394)

Key derivation for backups (iOS >= 10.2)::

    temp = PBKDF2-HMAC-SHA256(password, DPSL, DPIC, 32)
    dek  = PBKDF2-HMAC-SHA1(temp, SALT, ITER, 32)

...and for older backups the first stage does not exist::

    dek = PBKDF2-HMAC-SHA1(password, SALT, ITER, 32)

Every class key with the 0x02 flag is then unwrapped with ``dek``.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, Iterator, Tuple

from Crypto.Cipher import AES

BACKUP_KEYBAG = 1
DEVICE_KEYBAG = 0

WRAP_DEVICE = 0x01     # class key wrapped with the device UID key (unusable in backups)
WRAP_PASSCODE = 0x02   # class key wrapped with the passcode-derived key


class KeybagError(Exception):
    """Raised when a keybag cannot be parsed or unlocked."""


def _tlv_records(blob: bytes) -> Iterator[Tuple[bytes, bytes]]:
    """Yield ``(tag, value)`` pairs from a keybag blob."""
    offset = 0
    end = len(blob)
    while offset + 8 <= end:
        tag = blob[offset:offset + 4]
        length = struct.unpack(">I", blob[offset + 4:offset + 8])[0]
        start = offset + 8
        value = blob[start:start + length]
        if len(value) != length:  # truncated record
            break
        yield tag, value
        offset = start + length


def aes_key_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 AES key unwrap (a.k.a. AES-KW ``unwrap``).

    Returns the plaintext key, or raises :class:`KeybagError` when the
    integrity check fails (which normally means a wrong password).
    """
    if len(wrapped) % 8 or len(wrapped) < 16:
        raise KeybagError("wrapped key length must be a multiple of 8 and >= 16")
    n = len(wrapped) // 8 - 1
    a = struct.unpack(">Q", wrapped[:8])[0]
    r = [struct.unpack(">Q", wrapped[8 + i * 8:16 + i * 8])[0] for i in range(n)]

    cipher = AES.new(kek, AES.MODE_ECB)
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            block = cipher.decrypt(struct.pack(">Q", a ^ (n * j + i)) + struct.pack(">Q", r[i - 1]))
            a = struct.unpack(">Q", block[:8])[0]
            r[i - 1] = struct.unpack(">Q", block[8:])[0]

    if a != 0xA6A6A6A6A6A6A6A6:
        raise KeybagError("key unwrap failed (wrong password or corrupt keybag)")
    return b"".join(struct.pack(">Q", value) for value in r)


class ClassKey:
    """One protection-class record of a keybag."""

    __slots__ = ("class_id", "wrap_flags", "key_type", "wrapped_key", "key")

    def __init__(self, raw: Dict[bytes, bytes]) -> None:
        self.class_id = struct.unpack(">I", raw[b"CLAS"])[0]
        self.wrap_flags = struct.unpack(">I", raw[b"WRAP"])[0]
        self.key_type = struct.unpack(">I", raw.get(b"KTYP", b"\x00\x00\x00\x00"))[0]
        self.wrapped_key = raw[b"WPKY"]
        self.key = None  # filled in by Keybag.unlock()

    @property
    def passcode_protected(self) -> bool:
        return bool(self.wrap_flags & WRAP_PASSCODE)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "unlocked" if self.key else "locked"
        return f"<ClassKey {self.class_id} flags=0x{self.wrap_flags:02x} {state}>"


class Keybag:
    """A parsed backup keybag, able to derive class keys from a password."""

    def __init__(self, blob: bytes) -> None:
        self.blob = blob
        self.attrs: Dict[bytes, bytes] = {}
        self.class_keys: Dict[int, ClassKey] = {}
        self._parse()

    # -- parsing ---------------------------------------------------------
    def _parse(self) -> None:
        # Header fields come first; per-class records start at the first CLAS.
        in_class = False
        current: Dict[bytes, bytes] = {}
        for tag, value in _tlv_records(self.blob):
            if not in_class:
                if tag == b"CLAS":
                    in_class = True
                    current[tag] = value
                else:
                    self.attrs[tag] = value
                continue
            current[tag] = value
            if tag == b"WPKY":
                record = ClassKey(current)
                self.class_keys[record.class_id] = record
                current = {}

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Keybag":
        return cls(blob)

    # -- properties ------------------------------------------------------
    @property
    def version(self) -> int:
        return struct.unpack(">I", self.attrs.get(b"VERS", b"\x00\x00\x00\x00"))[0]

    @property
    def type(self) -> int:
        return struct.unpack(">I", self.attrs.get(b"TYPE", b"\x00\x00\x00\x00"))[0]

    @property
    def iterations(self) -> int:
        return struct.unpack(">I", self.attrs.get(b"ITER", b"\x00\x00\x00\x00"))[0]

    @property
    def double_protection_iterations(self) -> int:
        return struct.unpack(">I", self.attrs.get(b"DPIC", b"\x00\x00\x00\x00"))[0]

    @property
    def is_backup_keybag(self) -> bool:
        return self.type == BACKUP_KEYBAG

    @property
    def has_double_protection(self) -> bool:
        """iOS >= 10.2 wraps the passcode key twice (DPSL + DPIC stage)."""
        return b"DPSL" in self.attrs and b"DPIC" in self.attrs

    # -- unlocking -------------------------------------------------------
    def derive_key(self, password: str) -> bytes:
        """Derive the key-encryption key (KEK) from the backup password."""
        if not self.is_backup_keybag:
            raise KeybagError(
                "this is a device keybag (TYPE=%d), not a backup keybag" % self.type
            )
        for required in (b"SALT", b"ITER", b"WRAP"):
            if required not in self.attrs:
                raise KeybagError("keybag is missing the %s field" % required.decode())

        secret = password.encode("utf-8")
        if self.has_double_protection:
            secret = hashlib.pbkdf2_hmac(
                "sha256", secret, self.attrs[b"DPSL"], self.double_protection_iterations, 32
            )
        dek = hashlib.pbkdf2_hmac(
            "sha1", secret, self.attrs[b"SALT"], self.iterations, 32
        )
        # Some keybag versions (VERS=5) store a 4-byte flag instead of a wrapped
        # key in the header WRAP field, so only verify it when it is a real
        # 40-byte wrapped key. Wrong passwords are caught in unlock() anyway.
        header_wrap = self.attrs.get(b"WRAP") or b""
        if len(header_wrap) >= 16:
            try:
                aes_key_unwrap(dek, header_wrap)
            except KeybagError as exc:
                raise KeybagError("wrong backup password") from exc
        return dek

    def unlock(self, password: str) -> Dict[int, bytes]:
        """Derive and unwrap every passcode-protected class key.

        Returns ``{class_id: key}``. Raises :class:`KeybagError` on a wrong
        password, which is detected by the AES-KW integrity check.
        """
        dek = self.derive_key(password)
        unlocked: Dict[int, bytes] = {}
        for class_id, record in self.class_keys.items():
            if not record.passcode_protected:
                continue  # wrapped with the device UID key: useless for backups
            try:
                record.key = aes_key_unwrap(dek, record.wrapped_key)
            except KeybagError:
                continue
            unlocked[class_id] = record.key
        if not unlocked:
            raise KeybagError("wrong backup password (no class key could be unwrapped)")
        return unlocked

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Keybag v{self.version} type={self.type} "
            f"classes={sorted(self.class_keys)} iter={self.iterations}>"
        )
