"""Regression tests for ld-gc-sections-to-funcs."""

import io
import sys
from collections import defaultdict
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_script_module():
    """Load the executable script as an importable module for testing."""
    script_path = Path(__file__).resolve().parents[1] / "ld-gc-sections-to-funcs"
    loader = SourceFileLoader("ld_gc_sections_to_funcs", str(script_path))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_parse_text_section_name_keeps_clone_removals():
    """Clone-suffixed discarded sections should keep their raw symbol spelling."""
    module = load_script_module()

    assert module.parse_text_section_name(".text.foo.constprop.0") == "foo.constprop.0"
    assert module.parse_text_section_name(".text.foo.isra.3") == "foo.isra.3"
    assert (
        module.parse_text_section_name(
            ".text.do_deprecated_hypercall.isra.0",
        )
        == "do_deprecated_hypercall.isra.0"
    )
    assert module.parse_text_section_name(".text.foo.part.7") == "foo.part.7"
    assert module.parse_text_section_name(".text.foo.cold") == "foo.cold"
    assert (
        module.parse_text_section_name(".text.unlikely.foo.constprop.0")
        == "foo.constprop.0"
    )
    assert (
        module.parse_text_section_name(
            ".text.unlikely.__dt_translate_address.constprop.0",
        )
        == "__dt_translate_address.constprop.0"
    )


def test_normalize_name_strips_stacked_clone_suffixes():
    """Normalization should collapse repeated clone passes to one base name."""
    module = load_script_module()

    assert module.normalize_name("foo.constprop.0") == "foo"
    assert module.normalize_name("foo.constprop.0.isra.3") == "foo"
    assert module.normalize_name("foo.part.1.clone.2.cold") == "foo"


def test_extract_functions_from_fixture_log():
    """Linker logs on disk should parse into raw removed-body entries."""
    module = load_script_module()

    log_path = FIXTURES_DIR / "ld" / "extract-removals.log"

    entries = module.extract_functions(
        log_path.read_text(encoding="utf-8").splitlines(True),
        False,
    )

    assert entries == [
        module.RemovalEntry("helper", "lib.o", "helper.constprop.0"),
        module.RemovalEntry("helper", "lib.o", "helper"),
        module.RemovalEntry("foo", "lib.o", "foo.constprop.0"),
    ]


def test_pick_leaf_object_prefers_remaining_non_survivor():
    """A final-ELF survivor should let us pick the one removed candidate."""
    module = load_script_module()

    chosen, candidates = module.pick_leaf_object(
        "merge",
        ["a.o", "b.o"],
        defaultdict(set, {"merge": {"a.o"}}),
        set(),
    )

    assert chosen == "b.o"
    assert candidates == ["b.o"]


def test_matching_gcno_path_does_not_fall_back_to_basename(tmp_path):
    """A gcno in another directory must not satisfy a same-basename object."""
    module = load_script_module()

    target_dir = tmp_path / "target"
    other_dir = tmp_path / "other"
    target_dir.mkdir()
    other_dir.mkdir()

    obj_path = target_dir / "foo.o"
    gcno_path = other_dir / "foo.gcno"
    obj_path.write_bytes(b"")
    gcno_path.write_bytes(b"")

    assert module.matching_gcno_path(str(obj_path)) is None


def test_parse_dwarf_data_accepts_dw_at_language_name(monkeypatch):
    """Assembler detection should work when only `DW_AT_language_name` is present."""
    module = load_script_module()

    dwarf_lines = [
        "<0><0>: Abbrev Number: 1 (DW_TAG_compile_unit)",
        "    <1>   DW_AT_name        : asm.S",
        "    <2>   DW_AT_language_name: GNU Assembler",
        "<1><10>: Abbrev Number: 2 (DW_TAG_subprogram)",
        "    <11>   DW_AT_name        : asm_func",
        "    <12>   DW_AT_low_pc      : 0x0",
    ]

    monkeypatch.setattr(module, "iter_readelf", lambda _readelf, _path: dwarf_lines)

    dwarf_data = module.parse_dwarf_data(["asm.o"], "readelf")

    assert "asm_func" in dwarf_data.assembly_defined_names


def test_resolve_removed_entries_skips_partial_clone_removals(monkeypatch):
    """Removing one clone must not strip coverage for a live sibling body."""
    module = load_script_module()

    monkeypatch.setattr(module, "matching_gcno_path", lambda path: path.replace(".o", ".gcno"))
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set),
            defaultdict(set),
            defaultdict(
                lambda: defaultdict(set),
                {
                    "lib.o": defaultdict(
                        set,
                        {
                            "helper": {"helper", "helper.constprop.0"},
                        },
                    ),
                },
            ),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [module.RemovalEntry("helper", "lib.o", "helper.constprop.0")],
        False,
    )

    assert lines == []
    assert warnings == [
        "Skipping gcno removal for helper from lib.o: removed bodies "
        "(helper.constprop.0) still share coverage with live bodies (helper)"
    ]
    assert review_lines == [
        "# INFO skipped clone-only removal for helper from lib.o",
        "# reason: live out-of-line body still present",
        "# removed bodies: helper.constprop.0",
        "# remaining bodies: helper",
        "# helper",
        "",
    ]


def test_resolve_removed_entries_preserves_removed_body_after_leaf_resolution(monkeypatch):
    """Warnings should keep the raw body name after prelink-to-leaf resolution."""
    module = load_script_module()

    monkeypatch.setattr(
        module,
        "matching_gcno_path",
        lambda path: "lib.gcno" if path == "lib.o" else None,
    )
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set, {"helper": {"lib.o"}}),
            defaultdict(set, {"helper": {"lib.o"}}),
            defaultdict(
                lambda: defaultdict(set),
                {
                    "lib.o": defaultdict(
                        set,
                        {
                            "helper": {"helper", "helper.constprop.0"},
                        },
                    ),
                },
            ),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [module.RemovalEntry("helper", "prelink.o", "helper.constprop.0")],
        False,
    )

    assert lines == []
    assert warnings == [
        "Skipping gcno removal for helper from lib.o: removed bodies "
        "(helper.constprop.0) still share coverage with live bodies (helper)"
    ]
    assert review_lines == [
        "# INFO skipped clone-only removal for helper from lib.o",
        "# reason: live out-of-line body still present",
        "# removed bodies: helper.constprop.0",
        "# remaining bodies: helper",
        "# helper",
        "",
    ]


def test_resolve_removed_entries_keeps_clone_only_body_when_it_is_unique(monkeypatch):
    """A cloned body can still own the only gcov-covered implementation."""
    module = load_script_module()

    monkeypatch.setattr(module, "matching_gcno_path", lambda path: path.replace(".o", ".gcno"))
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set),
            defaultdict(set),
            defaultdict(
                lambda: defaultdict(set),
                {
                    "lib.o": defaultdict(
                        set,
                        {
                            "helper": {"helper.constprop.0"},
                        },
                    ),
                },
            ),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [module.RemovalEntry("helper", "lib.o", "helper.constprop.0")],
        False,
    )

    assert lines == ["lib.o:helper"]
    assert warnings == []
    assert review_lines == []


def test_resolve_removed_entries_reports_ambiguous_review(monkeypatch):
    """Ambiguous same-name candidates should become a review block by default."""
    module = load_script_module()

    monkeypatch.setattr(
        module,
        "matching_gcno_path",
        lambda path: {"a.o": "a.gcno", "b.o": "b.gcno"}.get(path),
    )
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set, {"merge": {"a.o", "b.o"}}),
            defaultdict(set, {"merge": {"a.o", "b.o"}}),
            defaultdict(lambda: defaultdict(set)),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [module.RemovalEntry("merge", "prelink.o", "merge")],
        False,
    )

    assert lines == []
    assert warnings == [
        "Ambiguous removal for merge: prelink.o matches multiple leaf objects "
        "(a.o, b.o)"
    ]
    assert review_lines == [
        "# REVIEW ambiguous removal for merge from prelink.o",
        "# candidates: a.o, b.o",
        "# merge",
        "",
    ]


def test_resolve_removed_entries_strict_raises_on_ambiguous(monkeypatch):
    """Strict mode should fail instead of emitting a review block."""
    module = load_script_module()

    monkeypatch.setattr(
        module,
        "matching_gcno_path",
        lambda path: {"a.o": "a.gcno", "b.o": "b.gcno"}.get(path),
    )
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set, {"merge": {"a.o", "b.o"}}),
            defaultdict(set, {"merge": {"a.o", "b.o"}}),
            defaultdict(lambda: defaultdict(set)),
        ),
    )

    with pytest.raises(RuntimeError, match="strict object matching failed"):
        module.resolve_removed_entries(
            [module.RemovalEntry("merge", "prelink.o", "merge")],
            True,
        )


def test_resolve_removed_entries_reports_likely_no_coverage(monkeypatch):
    """Leaf objects without gcno should become informational no-coverage notes."""
    module = load_script_module()

    monkeypatch.setattr(module, "matching_gcno_path", lambda _path: None)
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set),
            defaultdict(set, {"foo": {"arch/head.o"}}),
            defaultdict(lambda: defaultdict(set)),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [module.RemovalEntry("foo", "prelink.o", "foo")],
        False,
        module.DwarfResolutionState(set(), {"foo"}),
    )

    assert lines == []
    assert warnings == [
        "foo from prelink.o only matches leaf objects without gcno or DWARF "
        "function provenance (arch/head.o)"
    ]
    assert review_lines == [
        "# INFO likely assembly/no-coverage removal for foo from prelink.o",
        "# reason: no gcno coverage",
        "# candidates: arch/head.o",
        "# foo",
        "",
    ]


def test_main_writes_clone_suppression_fixture(tmp_path, monkeypatch):
    """The script should emit an explanatory info block for skipped clone removals."""
    module = load_script_module()
    log_path = FIXTURES_DIR / "ld" / "clone-only-removal.log"
    expected_path = FIXTURES_DIR / "ld" / "clone-only-removal.expected"
    output_path = tmp_path / "funcs-removed.cfg"

    (tmp_path / "lib.gcno").write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(set),
            defaultdict(set),
            defaultdict(
                lambda: defaultdict(set),
                {
                    "lib.o": defaultdict(
                        set,
                        {
                            "helper": {"helper", "helper.constprop.0"},
                        },
                    ),
                },
            ),
        ),
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(log_path.read_text(encoding="utf-8")))
    monkeypatch.setattr(
        sys,
        "argv",
        ["ld-gc-sections-to-funcs", "-o", str(output_path)],
    )

    assert module.main() == 0
    assert output_path.read_text(encoding="utf-8").lstrip("\n") == expected_path.read_text(
        encoding="utf-8"
    )
