#!/usr/bin/env python3
"""Localization completeness check.

A missing message key is not a cosmetic problem: the UI resolves an error's
``MessageKey`` through this catalog, so a gap shows the user a raw identifier such as
``error.route.bypass_failed`` at exactly the moment something has gone wrong.

Two distinct sets of strings are checked, and they are deliberately treated
differently:

* **Error codes** (``src/MyVpn.Core/Results/ErrorCodes.cs``) are machine-readable
  identifiers that appear in diagnostics bundles and across IPC. They must NEVER be
  localized, so they are excluded.
* **Message keys** are localization keys. A missing one is a defect, and this script
  fails.
* **Header catalog labels** (``header.*``) are consumed by the subscription-consent UI.
  They are checked and reported, and are allowed to fall back to English while that UI
  is still being built.

Usage:
    python3 build/check-localization.py [--strict-headers]

Exits non-zero when a message key is missing from any catalog, or when
``--strict-headers`` is given and a header label is missing from any catalog.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCALES = ROOT / "src" / "MyVpn.UI" / "Localization" / "locales"
ERROR_CODES = ROOT / "src" / "MyVpn.Core" / "Results" / "ErrorCodes.cs"

#: Files that legitimately contain key-shaped strings which are not localization keys.
EXCLUDED_DIRS = {"obj", "bin", ".git", ".tools", "node_modules"}
EXCLUDED_SUFFIXES = (".nupkg.sha512", ".nuspec", ".csproj", ".props", ".targets")

#: Literals that look like keys but are not.
NOT_KEYS = {
    "xray.exe",
    "resolv.conf",
    "resolv.conf.backup",
    "localhost.localdomain",
    "metadata.google.internal",
    "org.gnome.system.proxy",
    "org.gnome.system.proxy.http",
    "org.gnome.system.proxy.https",
    "org.gnome.system.proxy.socks",
    "geoip.dat",
    "geosite.dat",
}

#: Final path segments that mark a literal as a file name rather than a key.
FILE_EXTENSIONS = {
    "dat", "exe", "dll", "so", "dylib", "json", "conf", "pac", "cs", "axaml",
    "png", "svg", "log", "zip", "txt", "xml", "sh", "service", "desktop", "plist",
}

KEY_PATTERN = re.compile(r'"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"')
CODE_PATTERN = re.compile(r'=\s*"([^"]+)"')


def error_codes() -> set[str]:
    if not ERROR_CODES.exists():
        return set()
    return set(CODE_PATTERN.findall(ERROR_CODES.read_text(encoding="utf-8")))


def source_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for path in (ROOT / "src").rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.name.endswith(EXCLUDED_SUFFIXES):
            continue
        if path.suffix not in {".cs", ".axaml", ".json"}:
            continue
        files.append(path)
    return files


def referenced_keys() -> set[str]:
    keys: set[str] = set()
    for path in source_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for candidate in KEY_PATTERN.findall(text):
            if looks_like_key(candidate):
                keys.add(candidate)
    return keys


def looks_like_key(candidate: str) -> bool:
    """Filters out file names, versions and package identifiers.

    Error codes and message keys share a dotted lowercase shape with things like
    ``geoip.dat`` and ``go1.24.0``, so the shape alone is not enough.
    """
    if candidate in NOT_KEYS:
        return False

    segments = candidate.split(".")

    if segments[-1].lower() in FILE_EXTENSIONS:
        return False

    # A purely numeric segment means a version or dotted number, e.g. "go1.24.0".
    if any(segment.isdigit() for segment in segments):
        return False

    # Real keys are short and at most three levels deep (family.group.name).
    return len(segments) <= 3 and len(candidate) <= 48


def load(name: str) -> dict[str, str]:
    path = LOCALES / name
    if not path.exists():
        print(f"FATAL: missing catalog {path}", file=sys.stderr)
        sys.exit(2)
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict-headers",
        action="store_true",
        help="also fail when a header.* label is missing from a non-English catalog",
    )
    args = parser.parse_args()

    codes = error_codes()
    keys = referenced_keys()

    catalogs = {
        "en": load("en.json"),
        "ru": load("ru.json"),
        "zh-Hans": load("zh-Hans.json"),
    }

    def classify(key: str) -> str:
        if key in codes:
            return "code"
        return "header" if key.startswith("header.") else "message"

    messages = sorted(k for k in keys if classify(k) == "message")
    headers = sorted(k for k in keys if classify(k) == "header")

    failed = False

    print(f"error codes (never localized): {len(codes)}")
    print(f"message keys referenced      : {len(messages)}")
    print(f"header labels referenced     : {len(headers)}")
    print()

    for language, catalog in catalogs.items():
        missing_messages = [k for k in messages if k not in catalog]
        missing_headers = [k for k in headers if k not in catalog]

        status = "OK" if not missing_messages else "FAIL"
        print(f"{language:8s} keys={len(catalog):4d}  missing messages={len(missing_messages):3d}  "
              f"missing headers={len(missing_headers):3d}  [{status}]")

        for key in missing_messages:
            print(f"    MISSING MESSAGE: {key}")

        if missing_messages:
            failed = True

        if missing_headers:
            # Reported, not fatal: the catalog falls back to English, so the user sees a
            # readable label rather than a raw key. Tighten with --strict-headers once the
            # consent UI exists and its translations are complete.
            for key in missing_headers[:10]:
                print(f"    missing header : {key}")
            if len(missing_headers) > 10:
                print(f"    … and {len(missing_headers) - 10} more")

            if args.strict_headers:
                failed = True

    print()
    print("RESULT:", "FAIL" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
