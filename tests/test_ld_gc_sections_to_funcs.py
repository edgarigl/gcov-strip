"""Regression tests for ld-gc-sections-to-funcs."""

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from collections import defaultdict
from pathlib import Path


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
