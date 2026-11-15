# -*- coding: utf-8 -*-
"""End-to-end tests on a synthetic encrypted backup."""

import os
import struct

import pytest

from iosbackup_crypto.manifest import (
    Backup,
    BackupError,
    FileRecord,
    ManifestError,
    _decode_mb_file,
    _strip_pkcs7,
    find_backups,
)

from synth import build_backup, mb_file_blob


@pytest.fixture()
def sample(tmp_path):
    return build_backup(str(tmp_path))


def test_find_backups_accepts_udid_folder_and_parent(tmp_path, sample):
    assert find_backups(sample["backup_dir"]) == [sample["backup_dir"]]
    assert find_backups(str(tmp_path)) == [sample["backup_dir"]]


def test_info_reads_device_metadata(sample):
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        info = bak.info(count_files=True)
    assert info["device_name"] == "Test iPhone"
    assert info["ios_version"] == "17.4"
    assert info["encrypted"] is True
    assert info["keybag_version"] == 5
    assert info["file_count"] == len(sample["files"])


def test_wrong_password_is_rejected(sample):
    with pytest.raises(BackupError):
        Backup(sample["backup_dir"], password="nope")


def test_missing_password_is_rejected(sample):
    with pytest.raises(BackupError):
        Backup(sample["backup_dir"])


def test_read_file_decrypts_content(sample):
    with Backup(sample["backup_dir"], password=sample["password"], use_cache=False) as bak:
        for path, expected in sample["files"].items():
            assert bak.read_file(sample["domain"], path) == expected


def test_iter_files_and_metadata(sample):
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        records = {r.relative_path: r for r in bak.iter_files(domain=sample["domain"])}
    assert set(records) == set(sample["files"])
    first = records["Documents/notes.txt"]
    assert isinstance(first, FileRecord)
    assert first.size == len(sample["files"]["Documents/notes.txt"])
    assert first.protection_class == 3
    assert first.is_directory is False
    assert first.blob_path.endswith(first.file_id)


def test_glob_and_prefix_filters(sample):
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        globbed = [r.relative_path for r in bak.iter_files(glob="*.plist")]
        by_name = [r.relative_path for r in bak.iter_files(glob="com.example.plist")]
        prefixed = [
            r.relative_path for r in bak.iter_files(path_prefix="Documents/")
        ]
    assert globbed == ["Library/Preferences/com.example.plist"]
    assert by_name == ["Library/Preferences/com.example.plist"]  # matches the basename
    assert prefixed == ["Documents/notes.txt"]


def test_domains_lists_catalog(sample):
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        domains = bak.domains()
    assert domains == {sample["domain"]: len(sample["files"])}


def test_extract_writes_files_preserving_layout(tmp_path, sample):
    out = tmp_path / "out"
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        written = bak.extract(bak.iter_files(domain=sample["domain"]), str(out))
    assert len(written) == len(sample["files"])
    target = out / sample["domain"] / "Documents" / "notes.txt"
    assert target.read_bytes() == sample["files"]["Documents/notes.txt"]


def test_extract_skips_oversized_files(tmp_path, sample):
    out = tmp_path / "out2"
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        written = bak.extract(
            bak.iter_files(domain=sample["domain"]), str(out), max_size=1
        )
    assert written == []


def test_cached_manifest_db_is_reused(sample):
    first = Backup(sample["backup_dir"], password=sample["password"])
    cached = first.manifest_db()
    first.close()
    assert os.path.basename(cached) == "Manifest.dec.db"
    assert os.path.isfile(cached)

    second = Backup(sample["backup_dir"], password=sample["password"])
    assert second.manifest_db() == cached
    second.close()

    second.clear_cache()
    assert not os.path.exists(cached)


def test_legacy_manifest_mbdb_raises(tmp_path, sample):
    os.remove(os.path.join(sample["backup_dir"], "Manifest.db"))
    open(os.path.join(sample["backup_dir"], "Manifest.mbdb"), "wb").close()
    with Backup(sample["backup_dir"], password=sample["password"]) as bak:
        with pytest.raises(ManifestError):
            bak.manifest_db()


# --------------------------------------------------------------------------
# unit tests for the catalog decoders
# --------------------------------------------------------------------------
def test_decode_mb_file_reads_keyed_archive():
    blob = mb_file_blob("Documents/a.txt", 1234, b"\x00" * 40, class_id=3)
    meta = _decode_mb_file(blob)
    assert meta["Size"] == 1234
    assert meta["RelativePath"] == "Documents/a.txt"
    assert struct.unpack("<i", meta["EncryptionKey"][:4])[0] == 3


def test_decode_mb_file_handles_legacy_plain_dict():
    import plistlib

    blob = plistlib.dumps({"Size": 7, "RelativePath": "x"}, fmt=plistlib.FMT_BINARY)
    assert _decode_mb_file(blob)["Size"] == 7


def test_decode_mb_file_handles_garbage():
    assert _decode_mb_file(None) == {}
    assert _decode_mb_file(b"not a plist") == {}


def test_strip_pkcs7():
    assert _strip_pkcs7(b"abc" + b"\x01") == b"abc"
    assert _strip_pkcs7(b"ab" + b"\x02\x02") == b"ab"
    assert _strip_pkcs7(b"abc") == b"abc"  # not padding
    assert _strip_pkcs7(b"") == b""
