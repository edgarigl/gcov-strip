#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple


SECTION_RE = re.compile(
    r"removing unused section '([^']+)'", re.IGNORECASE
)
CLONE_SUFFIXES = (
    "constprop",
    "isra",
    "part",
    "clone",
)
CLONE_RE = re.compile(
    rf"^(?P<base>.+?)\.(?:{'|'.join(CLONE_SUFFIXES)})(?:\.\d+)?$"
)
DIE_RE = re.compile(
    r"^\s*<(?P<depth>\d+)><(?P<offset>[0-9a-fA-F]+)>: Abbrev Number: \d+ \((?P<tag>[^)]+)\)"
)
DWARF_NAME_RE = re.compile(r"DW_AT_name\s*:\s*(?P<value>.+)")
DWARF_LINKAGE_RE = re.compile(
    r"DW_AT_(?:linkage_name|MIPS_linkage_name)\s*:\s*(?P<value>.+)"
)
DWARF_ABSTRACT_ORIGIN_RE = re.compile(
    r"DW_AT_abstract_origin\s*:\s*(?:\([^)]*\)\s*)?<0x(?P<offset>[0-9a-fA-F]+)>"
)
DWARF_SPECIFICATION_RE = re.compile(
    r"DW_AT_specification\s*:\s*(?:\([^)]*\)\s*)?<0x(?P<offset>[0-9a-fA-F]+)>"
)
DWARF_LOW_PC_RE = re.compile(r"DW_AT_low_pc\b")
DWARF_RANGES_RE = re.compile(r"DW_AT_ranges\b")


def extract_functions(
    lines: Iterable[str],
    normalize_clones: bool,
    echo_stderr: bool,
) -> List[str]:
    functions: List[str] = []
    seen: Set[str] = set()
    for line in lines:
        if echo_stderr:
            sys.stderr.write(line)
        match = SECTION_RE.search(line)
        if not match:
            continue
        section = match.group(1)
        text_index = section.rfind(".text.")
        if text_index == -1:
            continue
        name = section[text_index + len(".text.") :]
        if normalize_clones:
            clone_match = CLONE_RE.match(name)
            if clone_match:
                name = clone_match.group("base")
        if name not in seen:
            seen.add(name)
            functions.append(name)
    return functions


def normalize_name(name: str, normalize_clones: bool) -> str:
    name = name.rstrip(".,")
    name = re.sub(r"/\d+$", "", name)
    if normalize_clones:
        clone_match = CLONE_RE.match(name)
        if clone_match:
            name = clone_match.group("base")
    return name


def iter_readelf(args: List[str]) -> Iterable[str]:
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace"
        )
    except FileNotFoundError as exc:
        raise RuntimeError("readelf not found") from exc
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")
    stderr = proc.stderr.read() if proc.stderr else ""
    returncode = proc.wait()
    if returncode != 0:
        raise RuntimeError(f"readelf failed: {' '.join(args)}\n{stderr}")


def clean_dwarf_value(value: str) -> str:
    value = value.strip()
    if "):" in value:
        value = value.split("):")[-1].strip()
    return value


def resolve_die_name(
    offset: int,
    die_by_offset: Dict[int, Dict[str, object]],
    normalize_clones: bool,
    visited: Optional[Set[int]] = None,
) -> Optional[str]:
    if visited is None:
        visited = set()
    if offset in visited:
        return None
    visited.add(offset)
    die = die_by_offset.get(offset)
    if not die:
        return None
    name = die.get("name") or die.get("linkage_name")
    if name:
        return normalize_name(str(name), normalize_clones)
    spec = die.get("specification")
    if isinstance(spec, int):
        resolved = resolve_die_name(spec, die_by_offset, normalize_clones, visited)
        if resolved:
            return resolved
    origin = die.get("abstract_origin")
    if isinstance(origin, int):
        return resolve_die_name(origin, die_by_offset, normalize_clones, visited)
    return None


def parse_dwarf_data(
    paths: Iterable[str],
    normalize_clones: bool,
) -> Tuple[Dict[str, Set[str]], Set[str]]:
    inlined_callers: Dict[str, Set[str]] = defaultdict(set)
    defined: Set[str] = set()
    for path in paths:
        die_by_offset: Dict[int, Dict[str, object]] = {}
        stack: List[int] = []
        current_offset: Optional[int] = None
        for line in iter_readelf(["readelf", "--debug-dump=info", "--wide", path]):
            header = DIE_RE.match(line)
            if header:
                depth = int(header.group("depth"))
                offset = int(header.group("offset"), 16)
                tag = header.group("tag")
                while len(stack) > depth:
                    stack.pop()
                parent = stack[-1] if stack else None
                die_by_offset[offset] = {
                    "tag": tag,
                    "name": None,
                    "linkage_name": None,
                    "abstract_origin": None,
                    "specification": None,
                    "parent": parent,
                    "has_code": False,
                }
                stack.append(offset)
                current_offset = offset
                continue
            if current_offset is None:
                continue
            if DWARF_LOW_PC_RE.search(line) or DWARF_RANGES_RE.search(line):
                die_by_offset[current_offset]["has_code"] = True
                continue
            match = DWARF_NAME_RE.search(line)
            if match:
                die_by_offset[current_offset]["name"] = clean_dwarf_value(
                    match.group("value")
                )
                continue
            match = DWARF_LINKAGE_RE.search(line)
            if match:
                die_by_offset[current_offset]["linkage_name"] = clean_dwarf_value(
                    match.group("value")
                )
                continue
            match = DWARF_ABSTRACT_ORIGIN_RE.search(line)
            if match:
                die_by_offset[current_offset]["abstract_origin"] = int(
                    match.group("offset"), 16
                )
                continue
            match = DWARF_SPECIFICATION_RE.search(line)
            if match:
                die_by_offset[current_offset]["specification"] = int(
                    match.group("offset"), 16
                )

        for offset, die in die_by_offset.items():
            if die.get("tag") == "DW_TAG_subprogram" and die.get("has_code"):
                name = resolve_die_name(offset, die_by_offset, normalize_clones)
                if name:
                    defined.add(name)
            if die.get("tag") != "DW_TAG_inlined_subroutine":
                continue
            abstract_origin = die.get("abstract_origin")
            if not isinstance(abstract_origin, int):
                continue
            callee = resolve_die_name(abstract_origin, die_by_offset, normalize_clones)
            parent = die.get("parent")
            caller = None
            while isinstance(parent, int):
                parent_die = die_by_offset.get(parent)
                if not parent_die:
                    break
                if parent_die.get("tag") == "DW_TAG_subprogram":
                    caller = resolve_die_name(parent, die_by_offset, normalize_clones)
                    break
                parent = parent_die.get("parent")
            if callee and caller:
                inlined_callers[callee].add(caller)
    return inlined_callers, defined


def find_inline_only_functions(
    remove_functions: Set[str],
    inline_info: Dict[str, Set[str]],
    defined_functions: Set[str],
) -> Set[str]:
    extra: Set[str] = set()
    for callee, callers in inline_info.items():
        if not callers or callee in remove_functions:
            continue
        if callee in defined_functions:
            continue
        if callers.issubset(remove_functions):
            extra.add(callee)
    return extra


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract removed function names from ld --print-gc-sections output."
    )
    parser.add_argument(
        "-n",
        "--normalize-clones",
        action="store_true",
        help="Normalize GCC clone suffixes like .constprop/.isra/.part/.clone.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Do not echo input lines to stderr.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write function list to this file instead of stdout.",
    )
    parser.add_argument(
        "--dwarf",
        action="append",
        default=[],
        help=(
            "Path to a binary/object file with DWARF info; may be repeated. "
            "Inline-only functions are added when all their inlined callers are removed."
        ),
    )
    args = parser.parse_args()

    functions = extract_functions(sys.stdin, args.normalize_clones, not args.quiet)
    seen = set(functions)
    inline_only: List[str] = []
    if args.dwarf:
        inlined, defined = parse_dwarf_data(args.dwarf, args.normalize_clones)
        inline_only = sorted(find_inline_only_functions(seen, inlined, defined))
        seen.update(inline_only)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            for name in functions:
                handle.write(f"{name}\n")
            if inline_only:
                handle.write("\n# Detected inline functions by DWARF scanning\n")
                for name in inline_only:
                    handle.write(f"{name}\n")
    else:
        for name in functions:
            print(name)
        if inline_only:
            print("\n# Detected inline functions by DWARF scanning")
            for name in inline_only:
                print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
