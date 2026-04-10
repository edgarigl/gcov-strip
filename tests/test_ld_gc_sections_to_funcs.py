"""Regression tests for ld-gc-sections-to-funcs."""

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import sys


def load_script_module():
    """Load the executable script as an importable module for testing."""
    script_path = Path(__file__).resolve().parents[1] / "ld-gc-sections-to-funcs"
    loader = SourceFileLoader("ld_gc_sections_to_funcs", str(script_path))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_parse_args_normalizes_clones_by_default(monkeypatch):
    """Clone normalization should be enabled unless explicitly disabled."""
    module = load_script_module()

    monkeypatch.setattr(sys, "argv", ["ld-gc-sections-to-funcs"])
    assert module.parse_args().normalize_clones is True

    monkeypatch.setattr(
        sys,
        "argv",
        ["ld-gc-sections-to-funcs", "--no-normalize-clones"],
    )
    assert module.parse_args().normalize_clones is False
def test_parse_text_section_name_keeps_clone_removals():
    """Clone-suffixed discarded sections should still map back to the base name."""
    module = load_script_module()

    assert module.parse_text_section_name(".text.foo.constprop.0", True) == "foo"
    assert module.parse_text_section_name(".text.foo.isra.3", True) == "foo"
    assert (
        module.parse_text_section_name(
            ".text.do_deprecated_hypercall.isra.0",
            True,
        )
        == "do_deprecated_hypercall"
    )
    assert module.parse_text_section_name(".text.foo.part.7", True) == "foo"
    assert module.parse_text_section_name(".text.foo.cold", True) == "foo"
    assert (
        module.parse_text_section_name(".text.unlikely.foo.constprop.0", True)
        == "foo"
    )
    assert (
        module.parse_text_section_name(
            ".text.unlikely.__dt_translate_address.constprop.0",
            True,
        )
        == "__dt_translate_address"
    )


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

    dwarf_data = module.parse_dwarf_data(["asm.o"], False, "readelf")

    assert "asm_func" in dwarf_data.assembly_defined_names
