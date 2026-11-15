# -*- coding: utf-8 -*-
"""Keybag parsing / key derivation tests (no real backup needed)."""

import hashlib
import struct

import pytest

from iosbackup_crypto.keybag import Keybag, KeybagError, aes_key_unwrap

from synth import aes_key_wrap, build_keybag, tlv, u32


# RFC 3394 test vector (section 4.1): 128-bit KEK, 128-bit key
RFC3394_KEK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
RFC3394_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
RFC3394_WRAPPED = bytes.fromhex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")


def test_aes_key_unwrap_rfc3394_vector():
    assert aes_key_unwrap(RFC3394_KEK, RFC3394_WRAPPED) == RFC3394_KEY


def test_aes_key_wrap_roundtrip():
    key = bytes(range(32))
    kek = bytes(range(32, 64))
    assert aes_key_unwrap(kek, aes_key_wrap(kek, key)) == key


def test_aes_key_unwrap_wrong_kek_raises():
    with pytest.raises(KeybagError):
        aes_key_unwrap(bytes(16), RFC3394_WRAPPED)


def test_aes_key_unwrap_rejects_bad_length():
    with pytest.raises(KeybagError):
        aes_key_unwrap(RFC3394_KEK, b"1234")


def test_keybag_parses_header_and_classes():
    class_key = bytes(range(32))
    blob = build_keybag("pw", {3: class_key, 11: bytes(range(32, 64))})
    keybag = Keybag.from_bytes(blob)

    assert keybag.version == 5
    assert keybag.type == 1
    assert keybag.is_backup_keybag
    assert keybag.iterations == 500
    assert keybag.double_protection_iterations == 800
    assert keybag.has_double_protection
    assert sorted(keybag.class_keys) == [3, 11]
    assert keybag.class_keys[3].passcode_protected


def test_keybag_unlock_returns_class_keys():
    class_key = bytes(range(32))
    keybag = Keybag.from_bytes(build_keybag("s3cret", {3: class_key}))
    unlocked = keybag.unlock("s3cret")
    assert unlocked == {3: class_key}


def test_keybag_unlock_wrong_password_raises():
    keybag = Keybag.from_bytes(build_keybag("s3cret", {3: bytes(32)}))
    with pytest.raises(KeybagError):
        keybag.unlock("wrong")


def test_keybag_legacy_without_double_protection():
    """Pre-iOS 10.2 backups skip the PBKDF2-SHA256 stage entirely."""
    class_key = bytes(range(32))
    blob = build_keybag("legacy-pw", {3: class_key}, double_protection=False)
    keybag = Keybag.from_bytes(blob)
    assert not keybag.has_double_protection

    expected_dek = hashlib.pbkdf2_hmac("sha1", b"legacy-pw", b"S" * 20, 500, 32)
    assert keybag.derive_key("legacy-pw") == expected_dek
    assert keybag.unlock("legacy-pw") == {3: class_key}


def test_keybag_skips_device_wrapped_classes():
    """Class keys without the 0x02 flag cannot be opened by the password."""
    dek_holder = Keybag.from_bytes(build_keybag("pw", {3: bytes(range(32))}))
    dek = dek_holder.derive_key("pw")

    blob = b"".join([
        tlv(b"VERS", u32(5)), tlv(b"TYPE", u32(1)), tlv(b"UUID", b"U" * 16),
        tlv(b"HMCK", bytes(40)), tlv(b"WRAP", u32(0)),
        tlv(b"SALT", b"S" * 20), tlv(b"ITER", u32(500)),
        tlv(b"DPWT", u32(1)), tlv(b"DPIC", u32(800)), tlv(b"DPSL", b"D" * 20),
        tlv(b"UUID", b"K" * 16), tlv(b"CLAS", u32(1)), tlv(b"WRAP", u32(1)),
        tlv(b"KTYP", u32(0)), tlv(b"WPKY", aes_key_wrap(dek, bytes(range(32)))),
    ])
    keybag = Keybag.from_bytes(blob)
    assert keybag.class_keys[1].passcode_protected is False
    with pytest.raises(KeybagError):
        keybag.unlock("pw")


def test_keybag_rejects_device_keybag():
    blob = tlv(b"VERS", u32(4)) + tlv(b"TYPE", u32(0))
    keybag = Keybag.from_bytes(blob)
    assert not keybag.is_backup_keybag
    with pytest.raises(KeybagError):
        keybag.unlock("pw")
