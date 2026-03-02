#!/usr/bin/env python3
import argparse
import os
import struct
import sys
from typing import Iterable, List, Optional, Set, Tuple


GCOV_TAG_FUNCTION = 0x01000000
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


def rebuild_gcno(
    data: bytes,
    remove_functions: Set[str],
) -> Tuple[bytes, int, List[str]]:
    if len(data) < GCOV_HEADER_SIZE:
        raise ValueError("missing gcno header")

    prefix_end = record_start_offset(data)
    output = bytearray()
    output.extend(data[:prefix_end])

    skip_current = False
    removed = 0
    removed_names: List[str] = []

    for tag, payload in iter_gcno_records(data, prefix_end):
        if tag == GCOV_TAG_FUNCTION:
            name = parse_function_name(payload)
            skip_current = name in remove_functions if name else False
            if skip_current:
                removed += 1
                if name:
                    removed_names.append(name)
                continue
        if skip_current:
            continue
        output.extend(struct.pack("<II", tag, len(payload)))
        output.extend(payload)

    return bytes(output), removed, removed_names


def find_gcno_files(root: str) -> Iterable[str]:
    for base, _, files in os.walk(root):
        for filename in files:
            if filename.endswith(".gcno"):
                yield os.path.join(base, filename)


def process_file(
    path: str, remove_functions: Set[str]
) -> Tuple[bool, int, List[str]]:
    with open(path, "rb") as handle:
        data = handle.read()

    updated, removed, removed_names = rebuild_gcno(data, remove_functions)
    if updated == data:
        return False, removed, removed_names

    with open(path, "wb") as handle:
        handle.write(updated)
    return True, removed, removed_names


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
                _, removed, removed_names = rebuild_gcno(data, remove_functions)
                changed = removed > 0
            else:
                changed, removed, removed_names = process_file(
                    path, remove_functions
                )
        except ValueError as exc:
            print(f"Skipping {path}: {exc}", file=sys.stderr)
            continue
        if args.verbose and removed_names:
            for name in removed_names:
                print(f"removed {name} from {path}")
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
