# -*- coding: utf-8 -*-
"""Command line interface for iosbackup-decrypt."""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import plistlib
import shutil
import sys
from typing import List, Optional

from . import __version__
from .keybag import KeybagError
from .manifest import (
    Backup,
    BackupError,
    ManifestError,
    default_backup_roots,
    default_cache_dir,
    find_backups,
)

EPILOG = """\
examples:
  # device / backup information (also verifies the password)
  iosbackup-decrypt -b "C:/.../MobileSync/Backup" info

  # list data domains, largest first
  iosbackup-decrypt domains --limit 20

  # list one app container
  iosbackup-decrypt ls --domain AppDomain-com.example.app

  # find files across all domains
  iosbackup-decrypt find '*.sqlite'

  # dump one app container, keeping the Documents/... layout
  iosbackup-decrypt extract --domain AppDomain-com.example.app --out ./dump

  # print one small text file
  iosbackup-decrypt cat --domain AppDomain-com.example.app --path Documents/config.json

The password is read from, in order: --password, --password-file,
$IOS_BACKUP_PASSWORD, or an interactive prompt.
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _setup_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def _fmt_size(num: Optional[int]) -> str:
    if not num:
        return "0 B"
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _fmt_time(stamp) -> str:
    try:
        return datetime.datetime.fromtimestamp(float(stamp)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _single_backup_dir(path: str) -> str:
    """Best-effort: the concrete backup folder (with Manifest.plist) for *path*."""
    candidates = find_backups(path)
    if candidates:
        return candidates[0]
    return path


def _needs_password(path: str) -> bool:
    try:
        with open(os.path.join(_single_backup_dir(path), "Manifest.plist"), "rb") as handle:
            return bool(plistlib.load(handle).get("IsEncrypted"))
    except Exception:
        return True


def _resolve_backup(args) -> str:
    if args.backup:
        return args.backup
    env = os.environ.get("IOS_BACKUP")
    if env:
        return env
    for root in default_backup_roots():
        if find_backups(root):
            return root
    raise BackupError(
        "no backup path given and none found in the default locations:\n  "
        + "\n  ".join(default_backup_roots())
    )


def _resolve_password(args, backup_path: str) -> Optional[str]:
    if not _needs_password(backup_path):
        return None
    if args.password:
        print(
            "warning: --password is visible to other processes; prefer --password-file "
            "or $IOS_BACKUP_PASSWORD",
            file=sys.stderr,
        )
        return args.password
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8-sig") as handle:
            return handle.readline().rstrip("\r\n")
    env = os.environ.get("IOS_BACKUP_PASSWORD")
    if env is not None:
        return env
    return getpass.getpass("Backup password: ")


def _open_backup(args) -> Backup:
    path = _resolve_backup(args)
    password = _resolve_password(args, path)
    return Backup(
        path,
        password=password,
        cache_dir=args.cache_dir,
        use_cache=not args.no_cache,
        verbose=args.verbose,
    )


def _print_json(payload) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_info(args) -> int:
    with _open_backup(args) as bak:
        info = bak.info(count_files=args.count)
        if args.json:
            _print_json(info)
            return 0
        pbkdf2 = f"{info['pbkdf2_iterations']:,}"
        if info["pbkdf2_double_iterations"]:
            pbkdf2 += f" + {info['pbkdf2_double_iterations']:,} (SHA-256 stage)"
        rows = [
            ("backup", info["backup_path"]),
            ("device", info["device_name"] or "-"),
            ("model", info["product_type"] or "-"),
            ("ios", f"{info['ios_version'] or '-'} ({info['build_version'] or '-'})"),
            ("udid", info["udid"]),
            ("last backup", info["last_backup"]),
            ("encrypted", "yes" if info["encrypted"] else "no"),
            ("passcode set", "yes" if info["passcode_set"] else "no"),
            ("Manifest.db", _fmt_size(info["manifest_db_size"])),
            ("keybag", f"v{info['keybag_version']} / TYPE={info['keybag_type']}"),
            ("pbkdf2", pbkdf2),
            ("classes", ", ".join(str(c) for c in info["unlocked_classes"]) or "-"),
        ]
        if "file_count" in info:
            rows.append(("files", f"{info['file_count']:,}"))
        width = max(len(label) for label, _ in rows)
        for label, value in rows:
            print(f"{label.ljust(width)}  {value}")
        return 0


def cmd_domains(args) -> int:
    with _open_backup(args) as bak:
        domains = bak.domains()
        items = list(domains.items())
        if args.limit:
            items = items[: args.limit]
        if args.json:
            _print_json(dict(items))
            return 0
        for domain, count in items:
            print(f"{count:>10,}  {domain}")
        if args.limit and len(domains) > args.limit:
            print(f"(showing {args.limit} of {len(domains)} domains; --limit 0 shows all)")
        return 0


def cmd_ls(args) -> int:
    with _open_backup(args) as bak:
        records = list(
            bak.iter_files(domain=args.domain, glob=args.glob, path_prefix=args.path)
        )
        if args.json:
            _print_json([r.as_dict() for r in records])
            return 0
        if not records:
            print("(no matching entries)")
            return 0
        total = sum(r.size for r in records if not r.is_directory)
        for record in records:
            kind = "d" if record.is_directory else "-"
            print(
                f"{kind} {_fmt_size(record.size):>9}  "
                f"{_fmt_time(record.modified):<19} {record.relative_path}"
            )
        print(f"\n{len(records)} entries, {_fmt_size(total)} total")
        return 0


def cmd_find(args) -> int:
    with _open_backup(args) as bak:
        records: List = []
        for record in bak.iter_files(domain=args.domain, glob=args.glob):
            records.append(record)
            if args.limit and len(records) >= args.limit:
                break
        if args.json:
            _print_json([r.as_dict() for r in records])
            return 0
        for record in records:
            print(f"{_fmt_size(record.size):>9}  {record.domain}  {record.relative_path}")
        print(f"\n{len(records)} entries")
        return 0


def cmd_extract(args) -> int:
    if not (args.domain or args.path or args.glob):
        raise BackupError(
            "refusing to extract every file of the backup; narrow it down with "
            "--domain / --path / --glob (or pass --all if you really mean it)"
        )
    out_dir = os.path.abspath(os.path.expanduser(args.out))
    with _open_backup(args) as bak:
        max_size = None if args.max_size is None else int(args.max_size * 1024 * 1024)
        count = skipped = 0
        total = 0
        for record in bak.iter_files(
            domain=args.domain, glob=args.glob, path_prefix=args.path
        ):
            if record.is_directory:
                continue
            if max_size is not None and record.size > max_size:
                skipped += 1
                continue
            name = record.relative_path.replace("/", "__" if args.flatten else os.sep)
            target = os.path.join(out_dir, "" if args.flatten else record.domain, name)
            if os.path.exists(target) and not args.overwrite:
                skipped += 1
                continue
            bak.extract_file(record, target)
            count += 1
            total += record.size
            if not args.quiet:
                print(f"[{_fmt_size(record.size):>9}] {record.domain}:{record.relative_path}")
        print(f"\nextracted {count} file(s), {_fmt_size(total)} -> {out_dir}")
        if skipped:
            print(f"skipped {skipped} file(s) (too large or already present; "
                  f"use --overwrite / --max-size)")
        return 0


def cmd_cat(args) -> int:
    with _open_backup(args) as bak:
        if args.path:
            record = bak.get_file(args.domain, args.path)
            if record is None:
                raise BackupError("not found: %s:%s" % (args.domain, args.path))
        else:
            matches = list(bak.iter_files(domain=args.domain, glob=args.glob or "*"))
            if len(matches) != 1:
                raise BackupError(
                    "expected exactly one match, got %d; narrow it down or use --path"
                    % len(matches)
                )
            record = matches[0]
        data = bak.read_file(record.domain, record.relative_path)
        if args.output:
            parent = os.path.dirname(os.path.abspath(args.output))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(args.output, "wb") as handle:
                handle.write(data)
            print("%d bytes -> %s" % (len(data), args.output), file=sys.stderr)
        else:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        return 0


def cmd_check(args) -> int:
    path = _resolve_backup(args)
    password = _resolve_password(args, path)
    if password is None:
        print("backup is not encrypted; no password needed")
        return 0
    with Backup(path, password=password, use_cache=False) as bak:
        print("password OK: unlocked classes %s" % sorted(bak.class_keys))
        print("Manifest.db decrypted successfully")
    return 0


def cmd_clean(args) -> int:
    path = _resolve_backup(args)
    candidates = find_backups(path)
    if not candidates:
        raise BackupError("no backup found at %r" % path)
    cache_root = args.cache_dir or default_cache_dir()
    removed = 0
    for candidate in candidates:
        udid = os.path.basename(candidate)
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in udid)
        folder = os.path.join(cache_root, safe)
        if os.path.isdir(folder):
            shutil.rmtree(folder, ignore_errors=True)
            removed += 1
            print("removed cache: %s" % folder)
    if not removed:
        print("no cache to remove")
    return 0


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------
def _common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-b", "--backup", metavar="PATH",
        help="backup folder (UDID folder or its parent); default: auto-detect",
    )
    parser.add_argument("--password", help="backup password (visible in the process list)")
    parser.add_argument("--password-file", metavar="FILE",
                        help="read the password from the first line of FILE")
    parser.add_argument("--no-cache", action="store_true",
                        help="do not keep a decrypted Manifest.db on disk")
    parser.add_argument("--cache-dir", metavar="DIR", help="cache location override")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iosbackup-decrypt",
        description="Decrypt and browse encrypted iOS/iPadOS backups "
                    "(Manifest.db and any file inside an app container).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _common_flags(parser)
    parser.add_argument("--version", action="version",
                        version="iosbackup-decrypt %s" % __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Each sub-parser also accepts the common flags so `... extract --backup X` works.
    # Their defaults are SUPPRESS so they never overwrite values given earlier.
    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text)
        _common_flags(p)
        for action in p._actions:
            if action.dest not in ("help",):
                action.default = argparse.SUPPRESS
        return p

    p = add("info", "device / backup info; verifies the password")
    p.add_argument("--count", action="store_true", help="count all catalog entries (slow)")
    p.set_defaults(func=cmd_info)

    p = add("domains", "list data domains with file counts")
    p.add_argument("--limit", type=int, default=0, help="only the N largest (0 = all)")
    p.set_defaults(func=cmd_domains)

    p = add("ls", "list catalog entries of one domain")
    p.add_argument("--domain", required=True)
    p.add_argument("--path", help="only entries below this relative path")
    p.add_argument("--glob", help="filter relative paths, e.g. '*.sqlite'")
    p.set_defaults(func=cmd_ls)

    p = add("find", "find files by path pattern")
    p.add_argument("glob", help="e.g. '*.sqlite' or 'Library/Preferences/*'")
    p.add_argument("--domain")
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_find)

    p = add("extract", "decrypt files into a folder")
    p.add_argument("--domain")
    p.add_argument("--path", help="only entries below this relative path")
    p.add_argument("--glob", help="filter relative paths")
    p.add_argument("--out", default="iosbackup-out", help="output folder")
    p.add_argument("--max-size", type=float, metavar="MB", help="skip files above this size")
    p.add_argument("--flatten", action="store_true", help="write everything into one folder")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(func=cmd_extract)

    p = add("cat", "print one decrypted file")
    p.add_argument("--domain", required=True)
    p.add_argument("--path")
    p.add_argument("--glob")
    p.add_argument("-o", "--output", help="write to a file instead of stdout")
    p.set_defaults(func=cmd_cat)

    p = add("check", "only verify the backup password")
    p.set_defaults(func=cmd_check)

    p = add("clean", "delete cached decrypted Manifest.db files")
    p.set_defaults(func=cmd_clean)

    return parser


_DEFAULTS = {
    "backup": None,
    "password": None,
    "password_file": None,
    "no_cache": False,
    "cache_dir": None,
    "verbose": False,
    "json": False,
}


def main(argv: Optional[List[str]] = None) -> int:
    _setup_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    for name, default in _DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)
    try:
        return args.func(args)
    except KeybagError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except (BackupError, ManifestError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
