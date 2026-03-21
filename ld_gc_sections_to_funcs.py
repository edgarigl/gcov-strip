#!/usr/bin/env python3
"""Convert linker `--print-gc-sections` output into removals for gcov-strip."""
# pylint: disable=too-many-lines
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
#
# The DWARF approach is intentionally conservative. It does not try to rebuild
# full linker provenance. Instead it asks a narrower question:
# - which inlined callees are described only as inline expansions in DWARF?
# - which out-of-line callers contain those inline expansions?
# - can both sides be mapped back to a concrete leaf object with a gcno file?
# If the callee has no concrete code range of its own and every observed caller
# was already removed by the linker, the callee becomes a candidate for gcno
# stripping as well. Missing or ambiguous object provenance leaves the entry in
# review-only form instead of widening the removal scope.
#
# Copyright (c) 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

FuncKey = Tuple[str, Optional[str]]
SymbolIndex = DefaultDict[str, Set[str]]


@dataclass
# pylint: disable=too-many-instance-attributes
class Die:
    """One parsed DWARF DIE entry from `readelf --debug-dump=info`."""

    tag: str                            # DIE tag, e.g. inlined_subroutine
    name: Optional[str] = None          # DW_AT_name source-level name
    linkage_name: Optional[str] = None  # linker-visible symbol name
    origin: Optional[int] = None        # referenced inline/cloned origin
    declaration: Optional[int] = None   # referenced declaration DIE
    parent: Optional[int] = None        # parent DIE offset in this CU
    has_code: bool = False              # has low_pc or ranges
    cu_offset: Optional[int] = None     # owning compile-unit offset
    cu_name: Optional[str] = None       # compile-unit source path
    cu_comp_dir: Optional[str] = None   # compile-unit working dir
    cu_language: Optional[str] = None   # compile-unit language string
    dwarf_object: Optional[str] = None  # scanned leaf-object path


DieMap = Dict[int, Die]


class DwarfResolutionState(NamedTuple):
    """Final-ELF DWARF state used while resolving removed functions."""

    final_defined_functions: Set[FuncKey]
    assembly_defined_names: Set[str]


class DwarfParseResult(NamedTuple):
    """Collected DWARF data used by the removal and inline-only passes."""

    inlined_callers: Dict[FuncKey, Set[FuncKey]]
    defined_functions: Set[FuncKey]
    final_defined_functions: Set[FuncKey]
    assembly_defined_names: Set[str]


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
# `DW_AT_name` is the generic source-level name field. Depending on the DIE, it
# may describe a compile unit's source file or a function's unmangled name.
DWARF_NAME_RE = re.compile(r"DW_AT_name\s*:\s*(?P<value>.+)")
# `DW_AT_comp_dir` gives the compilation directory for a compile unit so a
# relative `DW_AT_name` source path can be turned back into a likely object/gcno
# location.
DWARF_COMP_DIR_RE = re.compile(r"DW_AT_comp_dir\s*:\s*(?P<value>.+)")
# `DW_AT_language` lets us distinguish normal C compile units from assembler
# units that may still carry DWARF subprograms even though no gcno file exists.
DWARF_LANGUAGE_RE = re.compile(r"DW_AT_language\s*:\s*(?P<value>.+)")
# `DW_AT_linkage_name` / `DW_AT_MIPS_linkage_name` carry the linker-visible
# symbol name when the plain source-level `DW_AT_name` is not unique enough.
DWARF_LINKAGE_RE = re.compile(
    r"DW_AT_(?:linkage_name|MIPS_linkage_name)\s*:\s*(?P<value>.+)"
)
# `DW_AT_abstract_origin` points from an inline expansion or cloned concrete
# DIE back to the abstract DIE that owns the callee identity.
DWARF_ABSTRACT_ORIGIN_RE = re.compile(
    r"DW_AT_abstract_origin\s*:\s*(?:\([^)]*\)\s*)?<0x(?P<offset>[0-9a-fA-F]+)>"
)
# `DW_AT_specification` points from a concrete definition to a separate
# declaration DIE that may carry the canonical source-level name.
DWARF_SPECIFICATION_RE = re.compile(
    r"DW_AT_specification\s*:\s*(?:\([^)]*\)\s*)?<0x(?P<offset>[0-9a-fA-F]+)>"
)
# `DW_AT_low_pc` and `DW_AT_ranges` are the simplest cross-toolchain signals
# that a subprogram still has concrete machine code in the final DWARF view.
# If either is present, we treat the function as still having an out-of-line
# body and therefore not safe to auto-remove as "inline-only".
DWARF_LOW_PC_RE = re.compile(r"DW_AT_low_pc\b")
DWARF_RANGES_RE = re.compile(r"DW_AT_ranges\b")
NM_LINE_RE = re.compile(
    r"^(?:[0-9A-Fa-f]+\s+)?(?P<type>[A-Za-z])\s+(?P<name>\S+)$"
)


def extract_functions(
    lines: Iterable[str],
    normalize_clones: bool,
    echo_stderr: bool,
) -> List[FuncKey]:
    """Extract unique `(function, object)` removals from linker output."""
    # Pull unique `(function, object)` pairs from linker diagnostics such as:
    #   removing unused section '.text.foo' in file 'foo.o'
    #
    # Args:
    # - lines: linker output lines, usually stderr from the final link step.
    # - normalize_clones: collapse GCC clone suffixes back to the base function
    #   name so linker removals can be matched against gcov and DWARF names.
    # - echo_stderr: reprint the input line to stderr while parsing.
    #
    # Returns:
    # - a stable-order list of unique `(function_name, object_path)` tuples.
    functions: List[FuncKey] = []
    seen: Set[FuncKey] = set()
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
    """Normalize an object path into a stable key for gcno matching."""
    # Normalize linker-reported object paths into stable relative keys when
    # possible so they can be matched against gcno locations later.
    normalized = os.path.normpath(path)
    if os.path.isabs(normalized):
        try:
            return os.path.relpath(normalized, os.getcwd())
        except ValueError:
            return normalized
    return normalized


def object_gcno_candidates(path: str) -> Set[str]:
    """Return gcno path candidates for one object path."""
    # Linker diagnostics may report object paths in a few different forms. Try
    # the same path spellings when looking for the gcno file that would be
    # rewritten for an object-qualified removal.
    #
    # Args:
    # - path: an object path from linker output or DWARF-derived provenance.
    #
    # Returns:
    # - possible `.gcno` paths that might correspond to that object.
    normalized = normalize_object_path(path)
    candidates = {normalized}
    if not os.path.isabs(normalized):
        candidates.add(os.path.abspath(normalized))
        candidates.add(os.path.basename(normalized))
    gcno_candidates: Set[str] = set()
    for candidate in candidates:
        if candidate.endswith(".o"):
            gcno_candidates.add(candidate[:-2] + ".gcno")
    return gcno_candidates


def object_has_matching_gcno(path: str) -> bool:
    """Return true when an object path appears to own a gcno file."""
    # Treat an object as directly scopeable only when it has a corresponding
    # gcno file. Intermediate link artifacts often do not, which means they
    # need to be resolved back to leaf objects before we can safely scope a
    # removal to a specific gcno.
    return any(os.path.exists(candidate) for candidate in object_gcno_candidates(path))


def is_object_path(path: str) -> bool:
    """Return true when one DWARF input path is a leaf object file."""
    return path.endswith(".o")


def object_from_source_path(source_name: str, comp_dir: Optional[str]) -> Optional[str]:
    """Map a DWARF compile-unit source path back to a likely leaf object."""
    # DWARF compile units identify source files, not object files. In normal C
    # builds the object and gcno live next to the source path inside the build
    # tree, so try the obvious `.c -> .o` style translations and keep the first
    # one that actually has a matching gcno.
    #
    # Args:
    # - source_name: compile-unit source path from `DW_AT_name`.
    # - comp_dir: compile-unit working directory from `DW_AT_comp_dir`, or
    #   `None` when DWARF does not provide it.
    #
    # Returns:
    # - the first object path that appears to own the corresponding gcno, or
    #   `None` when the source file cannot be mapped back to a leaf object.
    candidates: List[str] = []
    if os.path.isabs(source_name):
        candidates.append(source_name)
    elif comp_dir:
        candidates.append(os.path.join(comp_dir, source_name))
    candidates.append(source_name)

    seen: Set[str] = set()
    for candidate in candidates:
        base, _ = os.path.splitext(candidate)
        obj_candidate = normalize_object_path(base + ".o")
        if obj_candidate in seen:
            continue
        seen.add(obj_candidate)
        if object_has_matching_gcno(obj_candidate):
            return obj_candidate
    return None


def iter_object_files(root: str) -> Iterable[str]:
    """Yield object files found under `root`."""
    for base, _, files in os.walk(root):
        for filename in files:
            if filename.endswith(".o"):
                yield os.path.join(base, filename)


def build_symbol_index(
    root: str,
    interesting_names: Set[str],
    normalize_clones: bool,
    require_gcno: bool,
) -> SymbolIndex:
    """Build `function -> leaf objects` for names relevant to this run."""
    # Index leaf object definitions for the names we care about so aggregate
    # linker removals like `prelink.o:foo` can be mapped back to `bar.o:foo`.
    #
    # Args:
    # - root: build-tree root to scan recursively for leaf object files.
    # - interesting_names: only these symbol names are indexed to keep the `nm`
    #   scan bounded to names that actually matter for the current run.
    # - normalize_clones: whether clone suffixes should be collapsed while
    #   indexing names from `nm`.
    #
    # Returns:
    # - `function_name -> {object_path, ...}` for leaf objects that appear to
    #   define the function. By default only objects with matching gcno files
    #   are indexed, but callers can also ask for all leaf objects.
    by_name: SymbolIndex = defaultdict(set)
    for obj_path in iter_object_files(root):
        rel_path = normalize_object_path(obj_path)
        if require_gcno and not object_has_matching_gcno(rel_path):
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


def build_gcno_symbol_index(
    root: str,
    interesting_names: Set[str],
    normalize_clones: bool,
) -> SymbolIndex:
    """Build `function -> leaf objects` for objects that own gcno files."""
    return build_symbol_index(root, interesting_names, normalize_clones, True)


def build_leaf_symbol_index(
    root: str,
    interesting_names: Set[str],
    normalize_clones: bool,
) -> SymbolIndex:
    """Build `function -> leaf objects` for all leaf objects under the tree."""
    return build_symbol_index(root, interesting_names, normalize_clones, False)


def build_removed_object_set(removed_entries: List[FuncKey]) -> Set[str]:
    """Return leaf objects that already appear in linker removals."""
    removed_objects: Set[str] = set()
    for _, obj_path in removed_entries:
        if obj_path and object_has_matching_gcno(obj_path):
            removed_objects.add(obj_path)
    return removed_objects


def build_surviving_symbol_index(defined_functions: Set[FuncKey]) -> SymbolIndex:
    """Index final-DWARF `function -> surviving objects` relationships."""
    surviving: SymbolIndex = defaultdict(set)
    for name, obj_path in defined_functions:
        if obj_path:
            surviving[name].add(obj_path)
    return surviving


def pick_leaf_object(
    name: str,
    leaf_objects: List[str],
    surviving_symbols: SymbolIndex,
    removed_objects: Set[str],
) -> Tuple[Optional[str], List[str]]:
    """Choose one removed leaf object and report the candidates considered."""
    if len(leaf_objects) == 1:
        return leaf_objects[0], leaf_objects

    # If final-ELF DWARF says which same-name leaf object survived, prefer the
    # remaining candidate. This is stronger than a name scan because it comes
    # from the actual linked image instead of just "who defines this name".
    surviving_objects = sorted(
        path for path in leaf_objects if path in surviving_symbols.get(name, set())
    )
    removed_candidates = [
        path for path in leaf_objects if path not in set(surviving_objects)
    ]
    if surviving_objects and len(removed_candidates) == 1:
        return removed_candidates[0], removed_candidates

    touched_objects = [path for path in leaf_objects if path in removed_objects]
    if len(touched_objects) == 1:
        return touched_objects[0], touched_objects

    return None, touched_objects or leaf_objects


class RemovalResolver:
    """Resolve removed functions into object-qualified config lines."""

    def __init__(
        self,
        removed_entries: List[FuncKey],
        normalize_clones: bool,
        strict: bool,
        dwarf_state: Optional[DwarfResolutionState] = None,
    ):
        """Build the indexes needed to scope removals to leaf objects."""
        dwarf_state = dwarf_state or DwarfResolutionState(set(), set())
        self.strict = strict
        self.gcno_symbol_index = build_gcno_symbol_index(
            os.getcwd(),
            {name for name, _ in removed_entries},
            normalize_clones,
        )
        self.leaf_symbol_index = build_leaf_symbol_index(
            os.getcwd(),
            {name for name, _ in removed_entries},
            normalize_clones,
        )
        self.removed_objects = build_removed_object_set(removed_entries)
        self.surviving_symbols = build_surviving_symbol_index(
            dwarf_state.final_defined_functions
        )
        self.defined_names = {
            name for name, _ in dwarf_state.final_defined_functions
        }
        self.assembly_defined_names = dwarf_state.assembly_defined_names

    def format_review_block(
        self,
        heading: str,
        detail_lines: List[str],
        name: str,
    ) -> List[str]:
        """Build one commented review/info block with a trailing blank line."""
        return [heading, *detail_lines, f"# {name}", ""]

    def resolve_one(
        self,
        name: str,
        obj_path: Optional[str],
    ) -> Tuple[List[str], List[str], List[str]]:
        """Turn one removed function into config lines, warnings, and reviews."""
        if obj_path and object_has_matching_gcno(obj_path):
            return [f"{obj_path}:{name}"], [], []

        leaf_objects = sorted(self.gcno_symbol_index.get(name, set()))
        chosen_object, candidate_objects = pick_leaf_object(
            name,
            leaf_objects,
            self.surviving_symbols,
            self.removed_objects,
        )

        if chosen_object is not None:
            return [f"{chosen_object}:{name}"], [], []

        if candidate_objects:
            return self.ambiguous_result(name, obj_path, candidate_objects)

        return self.unresolved_result(name, obj_path)

    def ambiguous_result(
        self,
        name: str,
        obj_path: Optional[str],
        candidate_objects: List[str],
    ) -> Tuple[List[str], List[str], List[str]]:
        """Return warnings and optional review lines for one ambiguous removal."""
        joined = ", ".join(candidate_objects)
        warnings = [
            f"Ambiguous removal for {name}: {obj_path or '<unknown object>'} "
            f"matches multiple leaf objects ({joined})"
        ]
        if self.strict:
            return [], warnings, []
        review_lines = self.format_review_block(
            "# REVIEW ambiguous removal for "
            f"{name} from {obj_path or '<unknown object>'}",
            [f"# candidates: {joined}"],
            name,
        )
        return [], warnings, review_lines

    def unresolved_result(
        self,
        name: str,
        obj_path: Optional[str],
    ) -> Tuple[List[str], List[str], List[str]]:
        """Return warnings and optional review lines for one unresolved removal."""
        uncovered_objects = sorted(
            path
            for path in self.leaf_symbol_index.get(name, set())
            if not object_has_matching_gcno(path)
        )
        if uncovered_objects and (
            name not in self.defined_names or name in self.assembly_defined_names
        ):
            return self.uncovered_result(name, obj_path, uncovered_objects)

        warnings = [
            f"Could not resolve {name} from {obj_path or '<unknown object>'} "
            "to a leaf object"
        ]
        if self.strict:
            return [], warnings, []
        review_lines = self.format_review_block(
            "# REVIEW unresolved removal for "
            f"{name} from {obj_path or '<unknown object>'}",
            ["# candidates: none"],
            name,
        )
        return [], warnings, review_lines

    def uncovered_result(
        self,
        name: str,
        obj_path: Optional[str],
        uncovered_objects: List[str],
    ) -> Tuple[List[str], List[str], List[str]]:
        """Return an info-style review block for likely non-covered code."""
        joined = ", ".join(uncovered_objects)
        warnings = [
            f"{name} from {obj_path or '<unknown object>'} only matches leaf "
            f"objects without gcno or DWARF function provenance ({joined})"
        ]
        if self.strict:
            return [], warnings, []
        review_lines = self.format_review_block(
            "# INFO likely assembly/no-coverage removal for "
            f"{name} from {obj_path or '<unknown object>'}",
            [
                "# reason: no gcno coverage",
                f"# candidates: {joined}",
            ],
            name,
        )
        return [], warnings, review_lines


def resolve_removed_entries(
    removed_entries: List[FuncKey],
    normalize_clones: bool,
    strict: bool,
    dwarf_state: Optional[DwarfResolutionState] = None,
) -> Tuple[List[str], List[str], List[str]]:
    """Turn removed entries into active config lines and review notes."""
    # Resolve linker removals into config lines.
    #
    # Resolution order:
    # 1. If the linker-reported object has its own gcno, emit it directly as
    #    `object:function`.
    # 2. Otherwise, if final-ELF DWARF identifies which same-name leaf object
    #    survived, choose the remaining candidate object as the removed one.
    # 3. Otherwise find leaf objects that define the same function name.
    # 4. If exactly one leaf object matches, use it.
    # 5. If several leaf objects match, prefer the one leaf object that also
    #    appears somewhere in the linker removal set.
    # 6. If resolution is still not unique, emit a `# REVIEW ...` block or fail
    #    in strict mode.
    #
    # Args:
    # - removed_entries: linker- or DWARF-derived `(function, object_hint)`
    #   tuples. `object_hint` may be `None` or may point at an intermediate
    #   object that does not own a gcno directly.
    # - normalize_clones: whether clone suffixes should be normalized while
    #   building the leaf-object symbol index.
    # - strict: if true, unresolved or ambiguous mappings raise an error instead
    #   of being emitted as commented review entries.
    # - dwarf_state: surviving DWARF state from non-`.o` inputs. The
    #   final-defined functions help identify which same-name leaf object
    #   survived in the linked image; the assembler-defined names keep
    #   assembler DWARF from blocking the likely no-coverage classification.
    #
    # Returns:
    # - active config lines safe for `gcov-strip`
    # - warning messages describing ambiguous or unresolved cases
    # - commented review lines to append to the generated config
    resolver = RemovalResolver(
        removed_entries,
        normalize_clones,
        strict,
        dwarf_state,
    )

    resolved_lines: List[str] = []
    warnings: List[str] = []
    review_lines: List[str] = []
    seen_lines: Set[str] = set()

    for name, obj_path in removed_entries:
        candidate_lines, entry_warnings, entry_review_lines = resolver.resolve_one(
            name,
            obj_path,
        )
        warnings.extend(entry_warnings)
        review_lines.extend(entry_review_lines)

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
    """Normalize a name so linker, DWARF, and gcov forms line up."""
    # Normalize names from DWARF/readelf output so they can be compared against
    # linker-derived names and gcov function records.
    name = name.rstrip(".,")
    name = re.sub(r"/\d+$", "", name)
    if normalize_clones:
        clone_match = CLONE_RE.match(name)
        if clone_match:
            name = clone_match.group("base")
    return name


def parse_object_scoped_entry(line: str) -> FuncKey:
    """Parse one `object:function` config line into `(function, object)`."""
    obj_path, function = line.rsplit(":", 1)
    if not obj_path or not function:
        raise RuntimeError(f"invalid object-scoped entry: {line}")
    return function, normalize_object_path(obj_path)


def iter_readelf(args: List[str]) -> Iterable[str]:
    """Stream `readelf` output line by line."""
    # Stream readelf output line-by-line so large DWARF dumps do not need to be
    # buffered in memory at once.
    try:
        with subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        ) as proc:
            assert proc.stdout is not None
            for line in proc.stdout:
                yield line.rstrip("\n")
            stderr = proc.stderr.read() if proc.stderr else ""
            returncode = proc.wait()
    except FileNotFoundError as exc:
        raise RuntimeError("readelf not found") from exc
    if returncode != 0:
        raise RuntimeError(f"readelf failed: {' '.join(args)}\n{stderr}")


def clean_dwarf_value(value: str) -> str:
    """Strip readelf formatting wrappers from one attribute value."""
    # readelf often prefixes attribute values with formatting metadata. Strip
    # that wrapper and keep just the human-readable symbol name.
    value = value.strip()
    if "):" in value:
        value = value.split("):")[-1].strip()
    return value


class DwarfScanner:
    """
    Small stateful DWARF scanner.

    The class keeps the current DIE table and the clone-normalization setting in
    one place so the inline-only inference reads more like a straight parser
    than a collection of generic helper calls.
    """

    def __init__(self, normalize_clones: bool):
        self.normalize_clones = normalize_clones
        self.die_by_offset: DieMap = {}
        self.assembly_defined_names: Set[str] = set()

    def object_hint(self, die: Die) -> Optional[str]:
        """
        Resolve the leaf object that should own the gcno for one DIE.
        """
        if die.dwarf_object and object_has_matching_gcno(die.dwarf_object):
            return normalize_object_path(die.dwarf_object)

        if die.cu_offset is None:
            return None
        cu_die = self.die_by_offset.get(die.cu_offset)
        if not cu_die:
            return None
        if not cu_die.cu_name:
            return None
        return object_from_source_path(
            cu_die.cu_name,
            cu_die.cu_comp_dir,
        )

    def resolve_identity(
        self,
        offset: int,
        visited: Optional[Set[int]] = None,
    ) -> Optional[FuncKey]:
        """
        Resolve both the function name and any object hint for one DIE.
        """
        if visited is None:
            visited = set()
        if offset in visited:
            return None
        visited.add(offset)

        die = self.die_by_offset.get(offset)
        if not die:
            return None

        name = die.name or die.linkage_name
        if name:
            return normalize_name(name, self.normalize_clones), self.object_hint(die)

        if die.declaration is not None:
            resolved = self.resolve_identity(die.declaration, visited)
            if resolved:
                return resolved

        if die.origin is not None:
            return self.resolve_identity(die.origin, visited)
        return None

    def scan_one(self, path: str) -> Tuple[Dict[FuncKey, Set[FuncKey]], Set[FuncKey]]:
        """
        Scan one DWARF input file and return inline relationships plus functions
        that still look defined out-of-line.
        """
        self.parse_path(path)
        return self.collect_results()

    def parse_path(self, path: str) -> None:
        """Parse one DWARF file into the current DIE table."""
        self.die_by_offset = {}
        stack: List[int] = []
        current_offset: Optional[int] = None
        current_cu_offset: Optional[int] = None
        dwarf_object_hint = normalize_object_path(path) if path.endswith(".o") else None

        for line in iter_readelf(["readelf", "--debug-dump=info", "--wide", path]):
            header = DIE_RE.match(line)
            if header:
                current_offset, current_cu_offset = self.start_die(
                    header, stack, current_cu_offset, dwarf_object_hint
                )
                continue

            if current_offset is None:
                continue

            self.parse_attr_line(current_offset, line)

    def start_die(
        self,
        header: re.Match[str],
        stack: List[int],
        current_cu_offset: Optional[int],
        dwarf_object_hint: Optional[str],
    ) -> Tuple[int, Optional[int]]:
        """Create one DIE from a readelf header line."""
        depth = int(header.group("depth"))
        offset = int(header.group("offset"), 16)
        tag = header.group("tag")

        while len(stack) > depth:
            stack.pop()

        parent = stack[-1] if stack else None
        if tag == "DW_TAG_compile_unit":
            current_cu_offset = offset

        self.die_by_offset[offset] = Die(
            tag=tag,
            parent=parent,
            cu_offset=current_cu_offset,
            dwarf_object=dwarf_object_hint,
        )
        stack.append(offset)
        return offset, current_cu_offset

    def collect_results(self) -> Tuple[Dict[FuncKey, Set[FuncKey]], Set[FuncKey]]:
        """Summarize the parsed DIE table as inline edges plus defined functions."""
        inlined_callers: Dict[FuncKey, Set[FuncKey]] = defaultdict(set)
        defined: Set[FuncKey] = set()
        for offset, die in self.die_by_offset.items():
            self.collect_defined(offset, die, defined)
            self.collect_inline_callers(die, inlined_callers)
        return inlined_callers, defined

    def collect_defined(
        self,
        offset: int,
        die: Die,
        defined: Set[FuncKey],
    ) -> None:
        """Record one function as defined when it still has code."""
        if die.tag != "DW_TAG_subprogram" or not die.has_code:
            return
        identity = self.resolve_identity(offset)
        if identity:
            defined.add(identity)
            if self.is_assembly_die(die):
                self.assembly_defined_names.add(identity[0])

    def collect_inline_callers(
        self,
        die: Die,
        inlined_callers: Dict[FuncKey, Set[FuncKey]],
    ) -> None:
        """Record one `inlined callee -> caller` relationship."""
        if die.tag != "DW_TAG_inlined_subroutine":
            return
        callee = self.resolve_inline_callee(die)
        caller = self.resolve_inlined_subroutine_caller(die)
        if callee and caller:
            inlined_callers[callee].add(caller)

    def parse_attr_line(self, current_offset: int, line: str) -> None:
        """
        Update one DIE from one readelf attribute line.
        """
        die = self.die_by_offset[current_offset]
        if DWARF_LOW_PC_RE.search(line) or DWARF_RANGES_RE.search(line):
            die.has_code = True
            return

        match = DWARF_NAME_RE.search(line)
        if match:
            value = clean_dwarf_value(match.group("value"))
            die.name = value

            if die.tag == "DW_TAG_compile_unit":
                die.cu_name = value
                die.cu_offset = current_offset
            return

        match = DWARF_COMP_DIR_RE.search(line)
        if match:
            die.cu_comp_dir = clean_dwarf_value(match.group("value"))
            return

        match = DWARF_LANGUAGE_RE.search(line)
        if match:
            die.cu_language = clean_dwarf_value(match.group("value"))
            return

        match = DWARF_LINKAGE_RE.search(line)
        if match:
            die.linkage_name = clean_dwarf_value(match.group("value"))
            return

        match = DWARF_ABSTRACT_ORIGIN_RE.search(line)
        if match:
            die.origin = int(match.group("offset"), 16)
            return

        match = DWARF_SPECIFICATION_RE.search(line)
        if match:
            die.declaration = int(match.group("offset"), 16)

    def resolve_inline_callee(self, die: Die) -> Optional[FuncKey]:
        """
        Resolve the callee identity for one `DW_TAG_inlined_subroutine` DIE.
        """
        if die.origin is None:
            return None
        return self.resolve_identity(die.origin)

    def resolve_inlined_subroutine_caller(
        self,
        die: Die,
    ) -> Optional[FuncKey]:
        """
        Follow parent DIEs until the enclosing caller function is found.
        """
        parent = die.parent
        while parent is not None:
            parent_die = self.die_by_offset.get(parent)
            if not parent_die:
                return None

            # An inlined-subroutine DIE is often nested inside lexical blocks,
            # try/catch regions, or other scope/container DIEs rather than
            # directly under the caller function DIE, so keep walking upward
            # until the first enclosing function is found.
            if parent_die.tag == "DW_TAG_subprogram":
                return self.resolve_identity(parent)
            parent = parent_die.parent
        return None

    def is_assembly_die(self, die: Die) -> bool:
        """Return true when one DIE belongs to an assembler compile unit."""
        if die.cu_offset is None:
            return False

        cu_die = self.die_by_offset.get(die.cu_offset)
        if not cu_die:
            return False

        if cu_die.cu_language and "assembler" in cu_die.cu_language.lower():
            return True

        if cu_die.cu_name and cu_die.cu_name.endswith((".S", ".s")):
            return True

        return False


def parse_dwarf_data(
    paths: Iterable[str],
    normalize_clones: bool,
) -> DwarfParseResult:
    """
    Scan DWARF inputs and collect inline-callee relationships plus subprograms
    that still appear to own concrete code ranges.

    Returns four pieces of state:
    - `inline callee -> callers`
    - all functions that still look defined out-of-line
    - functions defined in non-`.o` DWARF inputs, used as the final-ELF
      "surviving function" view during object resolution
    - function names whose DWARF provenance comes from assembler compile units
    """
    scanner = DwarfScanner(normalize_clones)
    inlined_callers: Dict[FuncKey, Set[FuncKey]] = defaultdict(set)
    defined: Set[FuncKey] = set()
    final_defined: Set[FuncKey] = set()
    for path in paths:
        file_inlined, file_defined = scanner.scan_one(path)
        defined.update(file_defined)
        if not is_object_path(path):
            final_defined.update(file_defined)

        for callee, callers in file_inlined.items():
            inlined_callers[callee].update(callers)
    return DwarfParseResult(
        inlined_callers,
        defined,
        final_defined,
        scanner.assembly_defined_names,
    )


def find_inline_only_functions(
    remove_functions: Set[FuncKey],
    inline_info: Dict[FuncKey, Set[FuncKey]],
    defined_functions: Set[FuncKey],
) -> Set[FuncKey]:
    """Infer safe inline-only removals from linker removals plus DWARF data."""
    # Infer extra removals for callees that only survive as inlined DWARF
    # entries and whose every caller is already known to be discarded.
    #
    # Args:
    # - remove_functions: already-confirmed removed functions, including object
    #   scope when known.
    # - inline_info: inline callee -> callers map from `parse_dwarf_data()`.
    # - defined_functions: functions that still have concrete code ranges in
    #   DWARF and therefore should not be treated as inline-only.
    #
    # Returns:
    # - additional scoped removals that are safe to infer from DWARF alone.
    extra: Set[FuncKey] = set()
    for callee, callers in inline_info.items():
        if not callers or callee in remove_functions:
            continue

        # Only auto-remove DWARF candidates when both the callee and its caller
        # set can be tied to concrete leaf objects. Otherwise the inference is
        # informational but not safe enough to rewrite gcno files.
        if callee[1] is None or any(caller[1] is None for caller in callers):
            continue

        if callee in defined_functions:
            continue

        if callers.issubset(remove_functions):
            extra.add(callee)
    return extra


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
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
            "object file. Ambiguous or unresolved entries become review "
            "comments without this flag."
        ),
    )
    parser.add_argument(
        "--dwarf",
        action="append",
        default=[],
        help=(
            "Path to a binary/object file with DWARF info; may be repeated. "
            "Inline-only functions are added when all their inlined callers "
            "are removed."
        ),
    )
    return parser.parse_args()


def resolve_inline_only_removals(
    args: argparse.Namespace,
    resolved_config_lines: List[str],
    inlined: Dict[FuncKey, Set[FuncKey]],
    defined: Set[FuncKey],
) -> Tuple[List[str], List[str], List[str]]:
    """Infer inline-only removals from DWARF and scope them to safe config lines."""
    # Start from the already-resolved linker removals, then ask DWARF for
    # extra callees that only survive as inline expansions. Any such callee
    # still has to go through the normal object-resolution path before it
    # becomes an active `object:function` config entry.
    if not inlined and not defined:
        return [], [], []

    resolved_removals = {
        parse_object_scoped_entry(line) for line in resolved_config_lines
    }
    inline_only_entries = sorted(
        find_inline_only_functions(resolved_removals, inlined, defined)
    )
    return resolve_removed_entries(
        inline_only_entries,
        args.normalize_clones,
        args.strict_object_match,
    )


def write_output(
    output_path: Optional[str],
    functions: List[str],
    inline_only: List[str],
    review_lines: List[str],
) -> None:
    """Write or print the generated config lines."""
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
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
        return

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


def main() -> int:
    """Glue linker parsing, DWARF inference, and config output together."""
    args = parse_args()

    try:
        dwarf_data = DwarfParseResult(defaultdict(set), set(), set(), set())
        if args.dwarf:
            dwarf_data = parse_dwarf_data(
                args.dwarf,
                args.normalize_clones,
            )

        removed_entries = extract_functions(sys.stdin, args.normalize_clones, not args.quiet)
        resolved_config_lines, warnings, review_lines = resolve_removed_entries(
            removed_entries,
            args.normalize_clones,
            args.strict_object_match,
            DwarfResolutionState(
                dwarf_data.final_defined_functions,
                dwarf_data.assembly_defined_names,
            ),
        )
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)

        inline_only, inline_warnings, inline_review_lines = resolve_inline_only_removals(
            args,
            resolved_config_lines,
            dwarf_data.inlined_callers,
            dwarf_data.defined_functions,
        )
        for warning in inline_warnings:
            print(f"warning: {warning}", file=sys.stderr)
        review_lines.extend(inline_review_lines)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    write_output(args.output, resolved_config_lines, inline_only, review_lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
