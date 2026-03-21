#!/usr/bin/env python3
"""Convert linker `--print-gc-sections` output into removals for gcov-strip."""
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

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple

FuncKey = Tuple[str, Optional[str]]
SymbolIndex = DefaultDict[str, Set[str]]
DieMap = Dict[int, Dict[str, object]]


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


def build_object_symbol_index(
    root: str,
    interesting_names: Set[str],
    normalize_clones: bool,
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
    #   define the function and also have a matching gcno file.
    by_name: SymbolIndex = defaultdict(set)
    for obj_path in iter_object_files(root):
        rel_path = normalize_object_path(obj_path)
        if not object_has_matching_gcno(rel_path):
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
    removed_entries: List[FuncKey],
    normalize_clones: bool,
    strict: bool,
) -> Tuple[List[str], List[str], List[str]]:
    """Turn removed entries into active config lines and review notes."""
    # Resolve linker removals into config lines. Direct leaf objects become
    # `object:function`; aggregate objects are mapped back to leaf objects via a
    # symbol index. Ambiguous or unresolved entries are emitted as commented
    # review notes unless strict mode is enabled.
    #
    # Args:
    # - removed_entries: linker- or DWARF-derived `(function, object_hint)`
    #   tuples. `object_hint` may be `None` or may point at an intermediate
    #   object that does not own a gcno directly.
    # - normalize_clones: whether clone suffixes should be normalized while
    #   building the leaf-object symbol index.
    # - strict: if true, unresolved or ambiguous mappings raise an error instead
    #   of being emitted as commented review entries.
    #
    # Returns:
    # - active config lines safe for `gcov-strip`
    # - warning messages describing ambiguous or unresolved cases
    # - commented review lines to append to the generated config
    interesting_names = {name for name, _ in removed_entries}
    symbol_index = build_object_symbol_index(os.getcwd(), interesting_names, normalize_clones)

    resolved_lines: List[str] = []
    warnings: List[str] = []
    review_lines: List[str] = []
    seen_lines: Set[str] = set()

    for name, obj_path in removed_entries:
        candidate_lines: List[str] = []

        if obj_path and object_has_matching_gcno(obj_path):
            # Leaf objects already line up with a single gcno file, so they can
            # be emitted directly as scoped `object:function` removals.
            candidate_lines = [f"{obj_path}:{name}"]
        else:
            leaf_objects = sorted(symbol_index.get(name, set()))
            if len(leaf_objects) == 1:
                # Intermediate link steps may report a combined object rather
                # than the leaf object that owns the gcno, so remap the name
                # back to its sole leaf object.
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
                        "# REVIEW ambiguous removal for "
                        f"{name} from {obj_path or '<unknown object>'}",
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
                        "# REVIEW unresolved removal for "
                        f"{name} from {obj_path or '<unknown object>'}",
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


def parse_scoped_entry(line: str) -> Tuple[str, Optional[str]]:
    """Parse one config line into `(function, object_hint)`."""
    # Config lines are either `function` or `object:function`. Keep the same
    # parser locally so linker-derived and DWARF-derived removals can share the
    # same scoped identity format.
    if ":" not in line:
        return line, None
    obj_path, function = line.rsplit(":", 1)
    if not obj_path or not function:
        return line, None
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

    def resolve_name(
        self,
        offset: int,
        visited: Optional[Set[int]] = None,
    ) -> Optional[str]:
        """
        Resolve the best symbol name for one DIE.
        """
        if visited is None:
            visited = set()
        if offset in visited:
            return None
        visited.add(offset)

        die = self.die_by_offset.get(offset)
        if not die:
            return None

        name = die.get("name") or die.get("linkage_name")
        if name:
            return normalize_name(str(name), self.normalize_clones)

        spec = die.get("specification")
        if isinstance(spec, int):
            resolved = self.resolve_name(spec, visited)
            if resolved:
                return resolved

        origin = die.get("abstract_origin")
        if isinstance(origin, int):
            return self.resolve_name(origin, visited)
        return None

    def object_hint(self, die: Dict[str, object]) -> Optional[str]:
        """
        Resolve the leaf object that should own the gcno for one DIE.
        """
        direct_object = die.get("dwarf_object")
        if isinstance(direct_object, str) and object_has_matching_gcno(direct_object):
            return normalize_object_path(direct_object)

        cu_offset = die.get("cu_offset")
        if not isinstance(cu_offset, int):
            return None
        cu_die = self.die_by_offset.get(cu_offset)
        if not cu_die:
            return None
        source_name = cu_die.get("cu_name")
        if not isinstance(source_name, str):
            return None
        comp_dir = cu_die.get("cu_comp_dir")
        return object_from_source_path(
            source_name,
            comp_dir if isinstance(comp_dir, str) else None,
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

        name = die.get("name") or die.get("linkage_name")
        if name:
            return normalize_name(str(name), self.normalize_clones), self.object_hint(die)

        spec = die.get("specification")
        if isinstance(spec, int):
            resolved = self.resolve_identity(spec, visited)
            if resolved:
                return resolved

        origin = die.get("abstract_origin")
        if isinstance(origin, int):
            return self.resolve_identity(origin, visited)
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

        self.die_by_offset[offset] = {
            "tag": tag,
            "name": None,
            "linkage_name": None,
            "abstract_origin": None,
            "specification": None,
            "parent": parent,
            "has_code": False,
            "cu_offset": current_cu_offset,
            "cu_name": None,
            "cu_comp_dir": None,
            "dwarf_object": dwarf_object_hint,
        }
        stack.append(offset)
        return offset, current_cu_offset

    def collect_results(self) -> Tuple[Dict[FuncKey, Set[FuncKey]], Set[FuncKey]]:
        """Collect inline relationships and still-defined functions."""
        inlined_callers: Dict[FuncKey, Set[FuncKey]] = defaultdict(set)
        defined: Set[FuncKey] = set()
        for offset, die in self.die_by_offset.items():
            self.collect_defined(offset, die, defined)
            self.collect_inline_callers(die, inlined_callers)
        return inlined_callers, defined

    def collect_defined(
        self,
        offset: int,
        die: Dict[str, object],
        defined: Set[FuncKey],
    ) -> None:
        """Record one subprogram as defined when it still has code."""
        if die.get("tag") != "DW_TAG_subprogram" or not die.get("has_code"):
            return
        identity = self.resolve_identity(offset)
        if identity:
            defined.add(identity)

    def collect_inline_callers(
        self,
        die: Dict[str, object],
        inlined_callers: Dict[FuncKey, Set[FuncKey]],
    ) -> None:
        """Record one `inlined callee -> caller` relationship."""
        if die.get("tag") != "DW_TAG_inlined_subroutine":
            return
        callee = self.resolve_inline_callee(die)
        caller = self.resolve_inline_caller(die)
        if callee and caller:
            inlined_callers[callee].add(caller)

    def parse_attr_line(self, current_offset: int, line: str) -> None:
        """
        Update one DIE from one readelf attribute line.
        """
        if DWARF_LOW_PC_RE.search(line) or DWARF_RANGES_RE.search(line):
            self.die_by_offset[current_offset]["has_code"] = True
            return

        match = DWARF_NAME_RE.search(line)
        if match:
            value = clean_dwarf_value(match.group("value"))
            self.die_by_offset[current_offset]["name"] = value

            if self.die_by_offset[current_offset].get("tag") == "DW_TAG_compile_unit":
                self.die_by_offset[current_offset]["cu_name"] = value
                self.die_by_offset[current_offset]["cu_offset"] = current_offset
            return

        match = DWARF_COMP_DIR_RE.search(line)
        if match:
            self.die_by_offset[current_offset]["cu_comp_dir"] = clean_dwarf_value(
                match.group("value")
            )
            return

        match = DWARF_LINKAGE_RE.search(line)
        if match:
            self.die_by_offset[current_offset]["linkage_name"] = clean_dwarf_value(
                match.group("value")
            )
            return

        match = DWARF_ABSTRACT_ORIGIN_RE.search(line)
        if match:
            self.die_by_offset[current_offset]["abstract_origin"] = int(
                match.group("offset"), 16
            )
            return

        match = DWARF_SPECIFICATION_RE.search(line)
        if match:
            self.die_by_offset[current_offset]["specification"] = int(
                match.group("offset"), 16
            )

    def resolve_inline_callee(self, die: Dict[str, object]) -> Optional[FuncKey]:
        """
        Resolve the callee identity for one `DW_TAG_inlined_subroutine` DIE.
        """
        abstract_origin = die.get("abstract_origin")
        if not isinstance(abstract_origin, int):
            return None
        return self.resolve_identity(abstract_origin)

    def resolve_inline_caller(self, die: Dict[str, object]) -> Optional[FuncKey]:
        """
        Walk parent DIEs upward until the containing subprogram is found.
        """
        parent = die.get("parent")
        while isinstance(parent, int):
            parent_die = self.die_by_offset.get(parent)
            if not parent_die:
                return None
            if parent_die.get("tag") == "DW_TAG_subprogram":
                return self.resolve_identity(parent)
            parent = parent_die.get("parent")
        return None


def parse_dwarf_data(
    paths: Iterable[str],
    normalize_clones: bool,
) -> Tuple[Dict[FuncKey, Set[FuncKey]], Set[FuncKey]]:
    """
    Scan DWARF inputs and collect inline-callee relationships plus subprograms
    that still appear to own concrete code ranges.
    """
    scanner = DwarfScanner(normalize_clones)
    inlined_callers: Dict[FuncKey, Set[FuncKey]] = defaultdict(set)
    defined: Set[FuncKey] = set()
    for path in paths:
        file_inlined, file_defined = scanner.scan_one(path)
        defined.update(file_defined)

        for callee, callers in file_inlined.items():
            inlined_callers[callee].update(callers)
    return inlined_callers, defined


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


def resolve_inline_only(
    args: argparse.Namespace,
    functions: List[str],
) -> Tuple[List[str], List[str], List[str]]:
    """Resolve extra inline-only removals from DWARF input."""
    if not args.dwarf:
        return [], [], []

    resolved_removals = {parse_scoped_entry(line) for line in functions}
    inlined, defined = parse_dwarf_data(args.dwarf, args.normalize_clones)
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
        removed_entries = extract_functions(sys.stdin, args.normalize_clones, not args.quiet)
        functions, warnings, review_lines = resolve_removed_entries(
            removed_entries, args.normalize_clones, args.strict_object_match
        )
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)

        inline_only, inline_warnings, inline_review_lines = resolve_inline_only(
            args, functions
        )
        for warning in inline_warnings:
            print(f"warning: {warning}", file=sys.stderr)
        review_lines.extend(inline_review_lines)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    write_output(args.output, functions, inline_only, review_lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
