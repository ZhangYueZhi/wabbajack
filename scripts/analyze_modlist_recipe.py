#!/usr/bin/env python3
"""Analyze a Wabbajack modlist recipe inside a .wabbajack archive or extracted modlist JSON."""

from __future__ import annotations

import argparse
import json
import string
import sys
import uuid
import zipfile
from collections import Counter, defaultdict
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
        return t.split(",", 1)[0].strip()
    return str(t)


def normalize_relpath(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
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


def collect_id_usages(directives: Iterable[dict[str, Any]]) -> dict[str, list[tuple[str, str, str]]]:
    usages: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for d in directives:
        dt = directive_type(d)
        to_path = normalize_relpath(d.get("To")) or "<no To>"
        for k in ID_FIELDS:
            if k in d:
                rid = normalize_relpath(d[k])
                if rid:
                    usages[rid].append((k, dt, to_path))
    return usages


def fmt_top(counter: Counter[str], top_n: int = 20) -> str:
    lines = []
    for name, count in counter.most_common(top_n):
        lines.append(f"  - {name}: {count}")
    if len(counter) > top_n:
        lines.append(f"  ... ({len(counter) - top_n} more)")
    return "\n".join(lines) if lines else "  (none)"


def is_guid_like(name: str) -> bool:
    try:
        uuid.UUID(name)
        return True
    except ValueError:
        return False


def sniff_payload(data: bytes) -> tuple[str, str]:
    if not data:
        return "empty", ""

    if data.startswith(b"PK\x03\x04"):
        return "zip", "nested zip container"
    if data[:2] == b"MZ":
        return "pe", "Windows executable/library header"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png", "PNG image"

    sample = data[:2048]
    printable = set(string.printable.encode("ascii"))
    ratio = sum(1 for b in sample if b in printable) / len(sample)
    if ratio > 0.95:
        try:
            txt = sample.decode("utf-8")
            preview = txt[:160].replace("\n", "\\n")
            return "text", preview
        except UnicodeDecodeError:
            pass

    return "binary", "non-text payload"


def analyze_guid_payloads(path: Path, id_usages: dict[str, list[tuple[str, str, str]]], limit: int) -> None:
    print("\n=== GUID Payload Analysis ===")
    with zipfile.ZipFile(path, "r") as zf:
        entries = [i for i in zf.infolist() if not i.is_dir()]
        guid_entries = [e for e in entries if is_guid_like(e.filename)]

        print(f"GUID-like entries in archive: {len(guid_entries)}")

        shown = 0
        for e in sorted(guid_entries, key=lambda x: x.filename):
            if shown >= limit:
                break
            with zf.open(e.filename, "r") as fp:
                data = fp.read(min(e.file_size, 8192))

            kind, detail = sniff_payload(data)
            usages = id_usages.get(e.filename, [])
            print(f"\n- {e.filename}")
            print(f"  size: {e.file_size} bytes")
            print(f"  inferred payload: {kind}{f' ({detail})' if detail else ''}")
            if usages:
                print(f"  usages: {len(usages)}")
                for field, dtype, to in usages[:5]:
                    print(f"    - field={field}, directive={dtype}, to={to}")
                if len(usages) > 5:
                    print(f"    ... ({len(usages) - 5} more)")
            else:
                print("  usages: 0 (orphan GUID entry)")
            shown += 1

        if len(guid_entries) > limit:
            print(f"\n... truncated: showing {limit}/{len(guid_entries)} GUID entries")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Wabbajack modlist recipe")
    parser.add_argument("input", type=Path, help="Path to .wabbajack or modlist/modlist.json")
    parser.add_argument("--show-missing", action="store_true", help="Print referenced IDs missing from zip")
    parser.add_argument("--show-orphan", action="store_true", help="Print zip entries that are not referenced")
    parser.add_argument("--analyze-guid", action="store_true", help="Inspect GUID payload files inside .wabbajack")
    parser.add_argument("--guid-limit", type=int, default=20, help="Max GUID entries to print (default: 20)")
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

    dict_directives = [d for d in directives if isinstance(d, dict)]
    d_counter = Counter(directive_type(d) for d in dict_directives)
    ids = collect_ids(dict_directives)
    id_usages = collect_id_usages(dict_directives)
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

    if args.analyze_guid:
        if args.input.suffix.lower() != ".wabbajack":
            print("\n--analyze-guid requires .wabbajack input", file=sys.stderr)
            return 2
        analyze_guid_payloads(args.input, id_usages, max(1, args.guid_limit))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
