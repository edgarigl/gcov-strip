#!/usr/bin/env python3
#
# Convert linker `--print-gc-sections` output into a list of function names
# whose coverage notes should be removed from `.gcno` files.
#
# The basic flow is:
# - scan linker stderr for discarded `.text.<function>` sections
# - optionally normalize GCC clone suffixes so names line up with gcov notes
# - optionally inspect DWARF to find inline-only callees whose out-of-line body
#   disappeared once all callers were garbage-collected
# - write the final function list to stdout or a config file consumed by
#   `gcov-strip`

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple


REMOVAL_RE = re.compile(
    r"removing unused section '([^']+)' in file '([^']+)'", re.IGNORECASE
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
NM_LINE_RE = re.compile(
    r"^(?:[0-9A-Fa-f]+\s+)?(?P<type>[A-Za-z])\s+(?P<name>\S+)$"
)
AGGREGATE_OBJECT_BASENAMES = {
    "built_in.o",
    "prelink.o",
    "libfdt.o",
    "libfdt-temp.o",
}


def extract_functions(
    lines: Iterable[str],
    normalize_clones: bool,
    echo_stderr: bool,
) -> List[Tuple[str, Optional[str]]]:
    # Pull unique `(function, object)` pairs from linker diagnostics such as:
    #   removing unused section '.text.foo' in file 'foo.o'
    functions: List[Tuple[str, Optional[str]]] = []
    seen: Set[Tuple[str, Optional[str]]] = set()
    for line in lines:
        if echo_stderr:
            sys.stderr.write(line)
        match = REMOVAL_RE.search(line)
        if not match:
            continue
        section, obj_path = match.groups()
        text_index = section.rfind(".text.")
        if text_index == -1:
            continue
        name = section[text_index + len(".text.") :]
        if normalize_clones:
            # GCC may emit clone-specific suffixes that should map back to the
            # original function name when matching against gcov notes.
            clone_match = CLONE_RE.match(name)
            if clone_match:
                name = clone_match.group("base")
        entry = (name, normalize_object_path(obj_path))
        if entry not in seen:
            seen.add(entry)
            functions.append(entry)
    return functions


def normalize_object_path(path: str) -> str:
    # Normalize linker-reported object paths into stable relative keys when
    # possible so they can be matched against gcno locations later.
    normalized = os.path.normpath(path)
    if os.path.isabs(normalized):
        try:
            return os.path.relpath(normalized, os.getcwd())
        except ValueError:
            return normalized
    return normalized


def is_aggregate_object(path: str) -> bool:
    # Aggregate objects collect many leaf objects into one partial link and do
    # not map 1:1 onto a single gcno file.
    return os.path.basename(path) in AGGREGATE_OBJECT_BASENAMES


def iter_object_files(root: str) -> Iterable[str]:
    for base, _, files in os.walk(root):
        for filename in files:
            if filename.endswith(".o"):
                yield os.path.join(base, filename)


def build_object_symbol_index(
    root: str,
    interesting_names: Set[str],
    normalize_clones: bool,
) -> DefaultDict[str, Set[str]]:
    # Index leaf object definitions for the names we care about so aggregate
    # linker removals like `prelink.o:foo` can be mapped back to `bar.o:foo`.
    by_name: DefaultDict[str, Set[str]] = defaultdict(set)
    for obj_path in iter_object_files(root):
        rel_path = normalize_object_path(obj_path)
        if is_aggregate_object(rel_path):
            continue
        try:
            output = subprocess.check_output(
                ["nm", "-a", obj_path],
                text=True,
                errors="replace",
                stderr=subprocess.DEVNULL,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise RuntimeError(f"nm failed for {obj_path}") from exc
        seen_in_object: Set[str] = set()
        for line in output.splitlines():
            match = NM_LINE_RE.match(line.strip())
            if not match:
                continue
            symbol_type = match.group("type")
            if symbol_type not in {"T", "t", "W", "w"}:
                continue
            name = normalize_name(match.group("name"), normalize_clones)
            if name not in interesting_names or name in seen_in_object:
                continue
            by_name[name].add(rel_path)
            seen_in_object.add(name)
    return by_name


def resolve_removed_entries(
    removed_entries: List[Tuple[str, Optional[str]]],
    normalize_clones: bool,
    strict: bool,
) -> Tuple[List[str], List[str], List[str]]:
    # Resolve linker removals into config lines. Direct leaf objects become
    # `object:function`; aggregate objects are mapped back to leaf objects via a
    # symbol index. Ambiguous or unresolved entries are emitted as commented
    # review notes unless strict mode is enabled.
    interesting_names = {name for name, _ in removed_entries}
    symbol_index = build_object_symbol_index(os.getcwd(), interesting_names, normalize_clones)

    resolved_lines: List[str] = []
    warnings: List[str] = []
    review_lines: List[str] = []
    seen_lines: Set[str] = set()

    for name, obj_path in removed_entries:
        candidate_lines: List[str] = []
        if obj_path and not is_aggregate_object(obj_path):
            # Leaf objects already line up with a single gcno file, so they can
            # be emitted directly as scoped `object:function` removals.
            candidate_lines = [f"{obj_path}:{name}"]
        else:
            leaf_objects = sorted(symbol_index.get(name, set()))
            if len(leaf_objects) == 1:
                # Aggregate link steps like `prelink.o` do not identify the gcno
                # to rewrite, so remap the name back to its sole leaf object.
                candidate_lines = [f"{leaf_objects[0]}:{name}"]
            elif len(leaf_objects) > 1:
                joined = ", ".join(leaf_objects)
                warnings.append(
                    f"Ambiguous removal for {name}: {obj_path or '<unknown object>'} "
                    f"matches multiple leaf objects ({joined})"
                )
                if strict:
                    continue
                # Leave ambiguous removals commented out by default so the
                # generated config is safe to consume without stripping coverage
                # from every gcno that happens to share the same function name.
                review_lines.extend(
                    [
                        f"# REVIEW ambiguous removal for {name} from {obj_path or '<unknown object>'}",
                        f"# candidates: {joined}",
                        f"# {name}",
                    ]
                )
            else:
                warnings.append(
                    f"Could not resolve {name} from {obj_path or '<unknown object>'} "
                    "to a leaf object"
                )
                if strict:
                    continue
                # Keep unresolved names out of the active config for the same
                # reason as ambiguous ones: a bare-name fallback would widen the
                # removal scope beyond what the linker actually proved.
                review_lines.extend(
                    [
                        f"# REVIEW unresolved removal for {name} from {obj_path or '<unknown object>'}",
                        "# candidates: none",
                        f"# {name}",
                    ]
                )
        for line in candidate_lines:
            if line not in seen_lines:
                seen_lines.add(line)
                resolved_lines.append(line)

    if strict and warnings:
        raise RuntimeError(
            "strict object matching failed:\n" + "\n".join(warnings)
        )
    return resolved_lines, warnings, review_lines


def normalize_name(name: str, normalize_clones: bool) -> str:
    # Normalize names from DWARF/readelf output so they can be compared against
    # linker-derived names and gcov function records.
    name = name.rstrip(".,")
    name = re.sub(r"/\d+$", "", name)
    if normalize_clones:
        clone_match = CLONE_RE.match(name)
        if clone_match:
            name = clone_match.group("base")
    return name


def iter_readelf(args: List[str]) -> Iterable[str]:
    # Stream readelf output line-by-line so large DWARF dumps do not need to be
    # buffered in memory at once.
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
    # readelf often prefixes attribute values with formatting metadata. Strip
    # that wrapper and keep just the human-readable symbol name.
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
    # Resolve a DIE name, following specification/abstract_origin links until a
    # concrete symbol name is found. `visited` prevents cycles in malformed or
    # unexpected DWARF graphs.
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
    # Build two indexes from DWARF:
    # - inline callee -> set of callers that inline it
    # - functions that still have an out-of-line code range somewhere
    #
    # A function can be safely treated as "inline-only removed" when it has no
    # out-of-line definition but every caller that inlined it was removed.
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
                # Keep a lightweight representation of each DIE so later passes
                # can resolve names and walk parent relationships.
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
                # Treat any concrete code range as evidence that the function
                # still exists out-of-line and should not be auto-removed.
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
                    # Walk up until we find the containing subprogram; that is
                    # the out-of-line function that performed the inline call.
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
    # Infer extra removals for callees that only survive as inlined DWARF
    # entries and whose every caller is already known to be discarded.
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
    # Glue the linker parser and optional DWARF analysis together, then emit a
    # flat text list suitable for `gcov-strip`.
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
        "--strict-object-match",
        action="store_true",
        help=(
            "Fail if a discarded function cannot be resolved to a single leaf "
            "object file. Without this flag, unresolved entries fall back to "
            "legacy bare-name output."
        ),
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

    try:
        removed_entries = extract_functions(sys.stdin, args.normalize_clones, not args.quiet)
        functions, warnings, review_lines = resolve_removed_entries(
            removed_entries, args.normalize_clones, args.strict_object_match
        )
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)

        removed_function_names = {name for name, _ in removed_entries}
        inline_only: List[str] = []
        if args.dwarf:
            inlined, defined = parse_dwarf_data(args.dwarf, args.normalize_clones)
            inline_only_names = sorted(
                find_inline_only_functions(removed_function_names, inlined, defined)
            )
            resolved_inline, inline_warnings, inline_review_lines = resolve_removed_entries(
                [(name, None) for name in inline_only_names],
                args.normalize_clones,
                args.strict_object_match,
            )
            for warning in inline_warnings:
                print(f"warning: {warning}", file=sys.stderr)
            review_lines.extend(inline_review_lines)
            inline_only = resolved_inline
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    seen = set(functions)
    seen.update(inline_only)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            for name in functions:
                handle.write(f"{name}\n")
            if inline_only:
                handle.write("\n# Detected inline functions by DWARF scanning\n")
                for name in inline_only:
                    handle.write(f"{name}\n")
            if review_lines:
                handle.write("\n")
                for line in review_lines:
                    handle.write(f"{line}\n")
    else:
        for name in functions:
            print(name)
        if inline_only:
            print("\n# Detected inline functions by DWARF scanning")
            for name in inline_only:
                print(name)
        if review_lines:
            print()
            for line in review_lines:
                print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
