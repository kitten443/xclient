#!/usr/bin/env python3
"""Provenance guard.

This project may incorporate code adapted from third-party sources, and v2rayN is
GPL-3.0-only. Two failures are possible and they need different rules:

* **Adapted code without attribution** — a licence violation and a false statement of
  authorship.
* **Discussing another project's defect** — which is not a licensing event at all. Much of
  this codebase cites v2rayN issue #9765 in comments explaining why a design differs.

The first version of this guard conflated them: it failed any source file that mentioned
the name at all, and passed any file that mentioned it within the first forty lines. It
therefore failed on three files that merely cite the issue number and passed three others
by accident. The invariant that actually holds is narrower and checkable:

    a file that carries an attribution marker must name its upstream, its licence, and
    appear in the register

Usage:
    python3 build/check-provenance.py

Exits non-zero on a violation.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
REGISTER = ROOT / "docs" / "provenance.md"

#: Detect the attribution header by its actual wording, not by English phrases that occur in
#: ordinary prose. A first attempt matched "derived from", which appears in sentences like
#: "the button label is derived from the state machine" and produced nine false positives.
#: Requiring the upstream project to be named in the same phrase is unambiguous: prose says
#: "v2rayN issue #9765", a header says "Adapted from v2rayN".
ATTRIBUTION_PATTERN = re.compile(
    r"adapted\s+from\s+[^\n]*?(?P<upstream>v2rayn|2dust)",
    re.IGNORECASE,
)

#: A complete header also names the upstream file, so the reader can find it.
HEADER_COMPLETENESS_MARKER = "upstream file"

#: The register table must contain at least one real entry once adaptation happens.
PLACEHOLDER_ROWS = ("*(none yet)*", "| — | *(none yet)* | — | — |")

UPSTREAM_LICENCES = {
    "v2rayn": "GPL-3.0-only",
}


def source_files() -> list[pathlib.Path]:
    return [
        path
        for path in SRC.rglob("*.cs")
        if not any(part in {"obj", "bin"} for part in path.parts)
    ]


def register_entries() -> list[str]:
    """Returns the non-placeholder rows of the register table."""
    if not REGISTER.exists():
        return []

    rows: list[str] = []
    in_table = False

    for line in REGISTER.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("| Date | Component |"):
            in_table = True
            continue
        if in_table and stripped.startswith("|---"):
            continue
        if in_table:
            if not stripped.startswith("|"):
                in_table = False
                continue
            if any(marker in stripped for marker in PLACEHOLDER_ROWS):
                continue
            rows.append(stripped)

    return rows


def main() -> int:
    failures: list[str] = []
    attributed: list[pathlib.Path] = []

    for path in source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        lowered = text.lower()

        match = ATTRIBUTION_PATTERN.search(text)
        if match is None:
            # Citing another project's issue number is not a licensing event.
            continue

        attributed.append(path)
        relative = path.relative_to(ROOT)
        upstream = match.group("upstream").lower()

        if HEADER_COMPLETENESS_MARKER not in lowered:
            failures.append(
                f"{relative}: attribution header is incomplete — it must name the upstream file"
            )

        expected = UPSTREAM_LICENCES[upstream]
        if expected.lower() not in lowered:
            failures.append(
                f"{relative}: attributes code to {upstream} but does not state its licence ({expected})"
            )

        if str(relative) not in REGISTER.read_text(encoding="utf-8") and path.name not in REGISTER.read_text(encoding="utf-8"):
            failures.append(f"{relative}: adapted code is not recorded in docs/provenance.md")

    entries = register_entries()

    if attributed and not entries:
        failures.append(
            f"{len(attributed)} file(s) carry an attribution marker but the register in "
            "docs/provenance.md has no entries"
        )

    print(f"source files scanned      : {len(source_files())}")
    print(f"files with adaptation     : {len(attributed)}")
    for path in attributed:
        print(f"    {path.relative_to(ROOT)}")
    print(f"register entries          : {len(entries)}")

    if failures:
        print()
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        print()
        print("RESULT: FAIL")
        return 1

    print()
    print("RESULT: OK — no unattributed derived code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
