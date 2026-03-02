#!/usr/bin/env python3
import argparse
import linecache
import os
import struct
import sys
from typing import Dict, Iterable, List, Optional, Set, Tuple


GCOV_TAG_FUNCTION = 0x01000000
GCOV_TAG_LINES = 0x01450000
GCOV_HEADER_SIZE = 16


def load_function_list(path: str) -> Set[str]:
    functions: Set[str] = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            functions.add(stripped)
    return functions


def record_start_offset(data: bytes) -> int:
    offset = GCOV_HEADER_SIZE
    if offset + 4 > len(data):
        raise ValueError("missing unit record")
    (length,) = struct.unpack_from("<I", data, offset)
    offset += 4
    if offset + length > len(data):
        raise ValueError("truncated unit record")
    offset += length
    if offset + 4 > len(data):
        raise ValueError("truncated unit record checksum")
    offset += 4
    return offset


def iter_gcno_records(data: bytes, start_offset: int) -> Iterable[Tuple[int, bytes]]:
    offset = start_offset
    while offset < len(data):
        if offset + 8 > len(data):
            raise ValueError("truncated record header")
        tag, length = struct.unpack_from("<II", data, offset)
        offset += 8
        if tag == 0:
            break
        if offset + length > len(data):
            raise ValueError("truncated record payload")
        payload = data[offset : offset + length]
        offset += length
        yield tag, payload


def read_gcov_string(payload: bytes, offset: int) -> Tuple[Optional[str], int]:
    if offset + 4 > len(payload):
        return None, offset
    (length,) = struct.unpack_from("<I", payload, offset)
    offset += 4
    if length == 0:
        return "", offset
    if offset + length > len(payload):
        return None, offset
    raw = payload[offset : offset + length]
    offset += length
    nul_index = raw.find(b"\x00")
    if nul_index != -1:
        raw = raw[:nul_index]
    return raw.decode("utf-8", errors="replace"), offset


def parse_function_name(payload: bytes) -> Optional[str]:
    if len(payload) < 12:
        return None
    offset = 12
    name, offset = read_gcov_string(payload, offset)
    if name is None:
        return None
    return name


def parse_line_record(payload: bytes) -> Dict[str, Set[int]]:
    if len(payload) < 4:
        return {}
    offset = 0
    offset += 4
    current_file: Optional[str] = None
    lines_by_file: Dict[str, Set[int]] = {}

    while offset + 4 <= len(payload):
        (line_number,) = struct.unpack_from("<I", payload, offset)
        offset += 4
        if line_number == 0:
            filename, offset = read_gcov_string(payload, offset)
            if filename is None:
                break
            if filename == "":
                break
            current_file = filename
            continue
        if not current_file:
            continue
        lines_by_file.setdefault(current_file, set()).add(line_number)

    return lines_by_file


def rebuild_gcno(
    data: bytes,
    remove_functions: Set[str],
    list_lines: bool = False,
) -> Tuple[bytes, int, List[str], List[Tuple[str, Dict[str, Set[int]]]]]:
    if len(data) < GCOV_HEADER_SIZE:
        raise ValueError("missing gcno header")

    prefix_end = record_start_offset(data)
    output = bytearray()
    output.extend(data[:prefix_end])

    skip_current = False
    removed = 0
    removed_names: List[str] = []
    removed_lines: List[Tuple[str, Dict[str, Set[int]]]] = []
    current_removed_lines: Optional[Dict[str, Set[int]]] = None

    for tag, payload in iter_gcno_records(data, prefix_end):
        if tag == GCOV_TAG_FUNCTION:
            name = parse_function_name(payload)
            skip_current = name in remove_functions if name else False
            if skip_current:
                removed += 1
                if name:
                    removed_names.append(name)
                if list_lines:
                    label = name if name else "<unknown>"
                    current_removed_lines = {}
                    removed_lines.append((label, current_removed_lines))
                continue
            current_removed_lines = None
        if skip_current and list_lines and tag == GCOV_TAG_LINES:
            if current_removed_lines is not None:
                parsed = parse_line_record(payload)
                for filename, lines in parsed.items():
                    current_removed_lines.setdefault(filename, set()).update(lines)
            continue
        if skip_current:
            continue
        output.extend(struct.pack("<II", tag, len(payload)))
        output.extend(payload)

    return bytes(output), removed, removed_names, removed_lines


def find_gcno_files(root: str) -> Iterable[str]:
    for base, _, files in os.walk(root):
        for filename in files:
            if filename.endswith(".gcno"):
                yield os.path.join(base, filename)


def process_file(
    path: str, remove_functions: Set[str], list_lines: bool = False
) -> Tuple[bool, int, List[str], List[Tuple[str, Dict[str, Set[int]]]]]:
    with open(path, "rb") as handle:
        data = handle.read()

    updated, removed, removed_names, removed_lines = rebuild_gcno(
        data, remove_functions, list_lines=list_lines
    )
    if updated == data:
        return False, removed, removed_names, removed_lines

    with open(path, "wb") as handle:
        handle.write(updated)
    return True, removed, removed_names, removed_lines


def resolve_source_path(gcno_path: str, source_name: str) -> str:
    if os.path.isabs(source_name):
        return source_name
    base_dir = os.path.dirname(gcno_path)
    candidate = os.path.join(base_dir, source_name)
    if os.path.exists(candidate):
        return candidate
    candidate = os.path.join(os.getcwd(), source_name)
    if os.path.exists(candidate):
        return candidate
    return os.path.join(base_dir, source_name)


def print_removed_lines(
    gcno_path: str, removed_lines: List[Tuple[str, Dict[str, Set[int]]]]
) -> None:
    for function_name, lines_by_file in removed_lines:
        if not lines_by_file:
            continue
        print(f"removed lines for {function_name} in {gcno_path}:")
        for filename in sorted(lines_by_file):
            source_path = resolve_source_path(gcno_path, filename)
            for line_number in sorted(lines_by_file[filename]):
                source_line = linecache.getline(source_path, line_number).rstrip("\n")
                if source_line:
                    print(f"{filename}:{line_number}: {source_line}")
                else:
                    print(f"{filename}:{line_number}")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Remove selected function records from .gcno files found "
            "recursively under the current directory."
        )
    )
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to a text file listing function names to remove.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report removals without modifying any files.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print per-file removal details.",
    )
    parser.add_argument(
        "--list-lines",
        action="store_true",
        help="List source lines associated with removed functions.",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    remove_functions = load_function_list(args.config)
    if not remove_functions:
        return 0 

    changed_files = 0
    total_removed = 0
    for path in find_gcno_files(os.getcwd()):
        try:
            if args.dry_run:
                with open(path, "rb") as handle:
                    data = handle.read()
                _, removed, removed_names, removed_lines = rebuild_gcno(
                    data, remove_functions, list_lines=args.list_lines
                )
                changed = removed > 0
            else:
                changed, removed, removed_names, removed_lines = process_file(
                    path, remove_functions, list_lines=args.list_lines
                )
        except ValueError as exc:
            print(f"Skipping {path}: {exc}", file=sys.stderr)
            continue
        if args.verbose and removed_names:
            for name in removed_names:
                print(f"removed {name} from {path}")
        if args.list_lines and removed_lines:
            print_removed_lines(path, removed_lines)
        if removed:
            total_removed += removed
        if changed:
            changed_files += 1

    print(
        f"Processed {changed_files} file(s); "
        f"removed {total_removed} function record(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
