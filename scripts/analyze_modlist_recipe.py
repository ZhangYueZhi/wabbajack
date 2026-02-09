#!/usr/bin/env python3
"""Analyze a Wabbajack modlist recipe inside a .wabbajack archive or extracted modlist JSON.

Features:
- Loads modlist from:
  1) .wabbajack zip (entry: modlist or modlist.json), or
  2) direct modlist JSON file.
- Summarizes directives by type.
- Finds inlined payload references (e.g. SourceDataID, PatchID, TempID).
- If input is .wabbajack, cross-checks referenced IDs vs zip entries.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


MODLIST_ENTRY_CANDIDATES = ("modlist", "modlist.json")
IGNORED_ZIP_ENTRIES = {"modlist", "modlist.json", "modlist-image.png"}
ID_FIELDS = ("SourceDataID", "PatchID", "TempID")


def load_modlist_from_zip(path: Path) -> tuple[dict[str, Any], set[str]]:
    with zipfile.ZipFile(path, "r") as zf:
        entries = {i.filename for i in zf.infolist() if not i.is_dir()}
        modlist_name = next((n for n in MODLIST_ENTRY_CANDIDATES if n in entries), None)
        if modlist_name is None:
            raise ValueError("No 'modlist' or 'modlist.json' entry found in archive")
        with zf.open(modlist_name, "r") as fp:
            modlist = json.load(fp)
        return modlist, entries


def load_modlist(path: Path) -> tuple[dict[str, Any], set[str] | None]:
    if path.suffix.lower() == ".wabbajack":
        modlist, entries = load_modlist_from_zip(path)
        return modlist, entries

    with path.open("r", encoding="utf-8") as fp:
        modlist = json.load(fp)
    return modlist, None


def directive_type(d: dict[str, Any]) -> str:
    t = d.get("$type") or d.get("Type") or "Unknown"
    if isinstance(t, str):
        # Legacy format can be "InlineFile, Wabbajack.Lib"
        return t.split(",", 1)[0].strip()
    return str(t)


def normalize_relpath(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        # Fallbacks for converter shapes
        for k in ("Path", "Value", "path", "value"):
            if k in v and isinstance(v[k], str):
                return v[k]
    return str(v)


def collect_ids(directives: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {k: set() for k in ID_FIELDS}
    for d in directives:
        for k in ID_FIELDS:
            if k in d:
                val = normalize_relpath(d[k])
                if val:
                    found[k].add(val)
    return found


def fmt_top(counter: Counter[str], top_n: int = 20) -> str:
    lines = []
    for name, count in counter.most_common(top_n):
        lines.append(f"  - {name}: {count}")
    if len(counter) > top_n:
        lines.append(f"  ... ({len(counter) - top_n} more)")
    return "\n".join(lines) if lines else "  (none)"


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Wabbajack modlist recipe")
    parser.add_argument("input", type=Path, help="Path to .wabbajack or modlist/modlist.json")
    parser.add_argument("--show-missing", action="store_true", help="Print referenced IDs missing from zip")
    parser.add_argument("--show-orphan", action="store_true", help="Print zip entries that are not referenced")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Input does not exist: {args.input}", file=sys.stderr)
        return 2

    try:
        modlist, zip_entries = load_modlist(args.input)
    except Exception as ex:  # noqa: BLE001
        print(f"Failed to load modlist: {ex}", file=sys.stderr)
        return 1

    directives = modlist.get("Directives") or []
    archives = modlist.get("Archives") or []

    if not isinstance(directives, list):
        print("Invalid modlist: Directives is not a list", file=sys.stderr)
        return 1
    if not isinstance(archives, list):
        print("Invalid modlist: Archives is not a list", file=sys.stderr)
        return 1

    d_counter = Counter(directive_type(d) for d in directives if isinstance(d, dict))
    ids = collect_ids([d for d in directives if isinstance(d, dict)])
    all_ids = set().union(*ids.values()) if ids else set()

    print("=== Modlist Recipe Summary ===")
    print(f"Name: {modlist.get('Name', '<unknown>')}")
    print(f"GameType: {modlist.get('GameType', '<unknown>')}")
    print(f"WabbajackVersion: {modlist.get('WabbajackVersion', '<unknown>')}")
    print(f"Archives count: {len(archives)}")
    print(f"Directives count: {len(directives)}")
    print("Directive types:")
    print(fmt_top(d_counter))
    print("\nReferenced inlined IDs:")
    for key in ID_FIELDS:
        print(f"  - {key}: {len(ids[key])}")
    print(f"  - Total unique IDs: {len(all_ids)}")

    if zip_entries is not None:
        data_entries = {e for e in zip_entries if e not in IGNORED_ZIP_ENTRIES}
        missing = sorted(all_ids - data_entries)
        orphan = sorted(data_entries - all_ids)

        print("\n=== Zip Cross-check ===")
        print(f"Zip entries (all files): {len(zip_entries)}")
        print(f"Zip data entries (excluding modlist/modlist-image): {len(data_entries)}")
        print(f"Referenced IDs present in zip: {len(all_ids) - len(missing)}")
        print(f"Referenced IDs missing in zip: {len(missing)}")
        print(f"Unreferenced zip data entries: {len(orphan)}")

        if args.show_missing and missing:
            print("\nMissing IDs:")
            for x in missing:
                print(f"  - {x}")

        if args.show_orphan and orphan:
            print("\nOrphan data entries:")
            for x in orphan:
                print(f"  - {x}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
