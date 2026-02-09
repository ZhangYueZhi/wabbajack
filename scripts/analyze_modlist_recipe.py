#!/usr/bin/env python3
"""Analyze a Wabbajack modlist recipe and generate detailed source-operation reports."""

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
NON_EXTRACT_TYPES = {"PatchedFromArchive", "TransformedTexture"}


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
        return load_modlist_from_zip(path)
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp), None


def directive_type(d: dict[str, Any]) -> str:
    t = d.get("$type") or d.get("Type") or "Unknown"
    return t.split(",", 1)[0].strip() if isinstance(t, str) else str(t)


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
    lines = [f"  - {name}: {count}" for name, count in counter.most_common(top_n)]
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
            return "text", txt[:160].replace("\n", "\\n")
        except UnicodeDecodeError:
            pass
    return "binary", "non-text payload"


def parse_archive_hash_path(v: Any) -> tuple[str | None, list[str]]:
    if isinstance(v, list) and v:
        return str(v[0]), [str(p) for p in v[1:]]
    if isinstance(v, dict):
        h = v.get("Hash")
        parts = v.get("Parts")
        if h is not None and isinstance(parts, list):
            return str(h), [str(p) for p in parts]
    return None, []


def operation_desc(d: dict[str, Any], d_type: str) -> str:
    if d_type == "FromArchive":
        return "extract file from archive"
    if d_type == "PatchedFromArchive":
        patch_id = normalize_relpath(d.get("PatchID")) or "<unknown patch>"
        return f"extract then apply binary patch ({patch_id})"
    if d_type == "TransformedTexture":
        state = d.get("ImageState")
        if state is not None:
            compact = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
            return f"extract then transform texture ({compact})"
        return "extract then transform texture"
    return d_type


def guid_payload_rows(wabbajack_path: Path, id_usages: dict[str, list[tuple[str, str, str]]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with zipfile.ZipFile(wabbajack_path, "r") as zf:
        for e in sorted((i for i in zf.infolist() if not i.is_dir()), key=lambda x: x.filename):
            if not is_guid_like(e.filename):
                continue
            with zf.open(e.filename, "r") as fp:
                sample = fp.read(min(e.file_size, 8192))
            kind, detail = sniff_payload(sample)
            usage = id_usages.get(e.filename, [])
            usage_summary = "; ".join(f"{f}:{t}->{to}" for f, t, to in usage[:5])
            if len(usage) > 5:
                usage_summary += f"; ... ({len(usage)-5} more)"
            rows.append(
                {
                    "id": e.filename,
                    "size": str(e.file_size),
                    "kind": kind,
                    "detail": detail,
                    "usage_count": str(len(usage)),
                    "usage_summary": usage_summary or "<none>",
                }
            )
    return rows


def generate_detailed_report(
    modlist: dict[str, Any],
    out_file: Path,
    wabbajack_path: Path | None,
    id_usages: dict[str, list[tuple[str, str, str]]],
) -> None:
    directives = [d for d in (modlist.get("Directives") or []) if isinstance(d, dict)]
    archives = [a for a in (modlist.get("Archives") or []) if isinstance(a, dict)]

    archive_meta: dict[str, dict[str, Any]] = {}
    for a in archives:
        h = a.get("Hash")
        if h is not None:
            archive_meta[str(h)] = a

    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    non_extract_rows: list[dict[str, str]] = []

    for d in directives:
        d_type = directive_type(d)
        if "ArchiveHashPath" not in d:
            continue
        h, parts = parse_archive_hash_path(d.get("ArchiveHashPath"))
        if h is None:
            continue

        source_in_archive = "\\".join(parts) if parts else "<archive-root>"
        to_path = normalize_relpath(d.get("To")) or "<no To>"
        op = operation_desc(d, d_type)

        arch = archive_meta.get(h, {})
        archive_name = str(arch.get("Name") or f"<unknown archive {h}>")
        state = arch.get("State")
        state_type = "UnknownState"
        if isinstance(state, dict):
            raw = str(state.get("$type") or state.get("Type") or "")
            if raw:
                state_type = raw.split(",", 1)[0].strip()

        row = {
            "archive_hash": h,
            "archive_state": state_type,
            "directive": d_type,
            "source": source_in_archive,
            "to": to_path,
            "operation": op,
        }
        grouped[archive_name].append(row)
        if d_type in NON_EXTRACT_TYPES:
            non_extract_rows.append({"archive": archive_name, **row})

    guid_rows = guid_payload_rows(wabbajack_path, id_usages) if wabbajack_path else []

    with out_file.open("w", encoding="utf-8") as f:
        f.write("# Wabbajack Detailed Recipe Report\n\n")
        f.write(f"- Name: {modlist.get('Name', '<unknown>')}\n")
        f.write(f"- GameType: {modlist.get('GameType', '<unknown>')}\n")
        f.write(f"- WabbajackVersion: {modlist.get('WabbajackVersion', '<unknown>')}\n")
        f.write(f"- Archive groups (mods): {len(grouped)}\n")
        total_rows = sum(len(v) for v in grouped.values())
        f.write(f"- File operations from archives: {total_rows}\n")
        f.write(f"- **Non-extract operations**: {len(non_extract_rows)}\n")
        f.write(f"- GUID payload entries analyzed: {len(guid_rows)}\n\n")

        f.write("## ⚠️ Non-extract operations (重点关注)\n\n")
        if not non_extract_rows:
            f.write("None. All archive-linked operations are plain extract.\n\n")
        else:
            c = Counter(r["directive"] for r in non_extract_rows)
            for k, v in c.most_common():
                f.write(f"- {k}: {v}\n")
            f.write("\n| Archive | Directive | Source In Archive | Destination | Operation |\n")
            f.write("|---|---|---|---|---|\n")
            for r in non_extract_rows:
                src = r['source'].replace('|', '\\|')
                dst = r['to'].replace('|', '\\|')
                op = r['operation'].replace('|', '\\|')
                f.write(f"| {r['archive']} | {r['directive']} | `{src}` | `{dst}` | {op} |\n")
            f.write("\n")

        if guid_rows:
            f.write("## GUID payload content analysis\n\n")
            f.write("| GUID Entry | Size | Inferred Kind | Detail/Preview | Usage Count | Usage Summary |\n")
            f.write("|---|---:|---|---|---:|---|\n")
            for r in guid_rows:
                detail = r["detail"].replace("|", "\\|")
                usage = r["usage_summary"].replace("|", "\\|")
                f.write(
                    f"| `{r['id']}` | {r['size']} | {r['kind']} | {detail} | {r['usage_count']} | {usage} |\n"
                )
            f.write("\n")

        for mod_name in sorted(grouped.keys()):
            rows = grouped[mod_name]
            counter = Counter(r["directive"] for r in rows)
            first = rows[0]
            f.write(f"## {mod_name}\n\n")
            f.write(f"- Archive hash: `{first['archive_hash']}`\n")
            f.write(f"- Archive state: `{first['archive_state']}`\n")
            f.write(f"- Operation count: {len(rows)}\n")
            f.write("- Directive breakdown:\n")
            for k, c in counter.most_common():
                f.write(f"  - {k}: {c}\n")
            f.write("\n| Directive | Source In Archive | Destination | Operation |\n")
            f.write("|---|---|---|---|\n")
            for r in rows:
                src = r["source"].replace("|", "\\|")
                dst = r["to"].replace("|", "\\|")
                op = r["operation"].replace("|", "\\|")
                f.write(f"| {r['directive']} | `{src}` | `{dst}` | {op} |\n")
            f.write("\n")


def analyze_guid_payloads(path: Path, id_usages: dict[str, list[tuple[str, str, str]]], limit: int) -> None:
    print("\n=== GUID Payload Analysis ===")
    rows = guid_payload_rows(path, id_usages)
    print(f"GUID-like entries in archive: {len(rows)}")
    for row in rows[:limit]:
        print(f"\n- {row['id']}")
        print(f"  size: {row['size']} bytes")
        print(f"  inferred payload: {row['kind']} ({row['detail']})")
        print(f"  usages: {row['usage_count']}")
        print(f"    {row['usage_summary']}")
    if len(rows) > limit:
        print(f"\n... truncated: showing {limit}/{len(rows)} GUID entries")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Wabbajack modlist recipe")
    parser.add_argument("input", type=Path, help="Path to .wabbajack or modlist/modlist.json")
    parser.add_argument("--show-missing", action="store_true", help="Print referenced IDs missing from zip")
    parser.add_argument("--show-orphan", action="store_true", help="Print zip entries that are not referenced")
    parser.add_argument("--analyze-guid", action="store_true", help="Inspect GUID payload files inside .wabbajack")
    parser.add_argument("--guid-limit", type=int, default=20, help="Max GUID entries to print (default: 20)")
    parser.add_argument(
        "--detailed-report-out",
        type=Path,
        help="Write detailed markdown report: which destination file comes from which archive and operation",
    )
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

    non_extract_count = sum(1 for d in dict_directives if directive_type(d) in NON_EXTRACT_TYPES)
    print(f"\n⚠️ Non-extract archive operations: {non_extract_count}")
    if non_extract_count:
        print("   Includes directive types: " + ", ".join(sorted(NON_EXTRACT_TYPES & set(d_counter.keys()))))

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

    if args.detailed_report_out is not None:
        args.detailed_report_out.parent.mkdir(parents=True, exist_ok=True)
        wj = args.input if args.input.suffix.lower() == ".wabbajack" else None
        generate_detailed_report(modlist, args.detailed_report_out, wj, id_usages)
        print(f"\nDetailed report written: {args.detailed_report_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
