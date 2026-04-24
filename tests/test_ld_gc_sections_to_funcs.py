"""Regression tests for ld-gc-sections-to-funcs."""

import io
import os
import shutil
import subprocess
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


def script_path():
    """Return the standalone ld-gc-sections-to-funcs script path."""
    return Path(__file__).resolve().parents[1] / "ld-gc-sections-to-funcs"


def run_command(args, cwd):
    """Run one subprocess and return the completed result."""
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def write_same_name_static_source(path, stem, keep_shared, bias):
    """Write one object source with a live and dead wrapper around `shared`."""
    if keep_shared:
        live_body = f"    return shared({bias});"
        dead_body = "    return 0;"
    else:
        live_body = f"    return {bias};"
        dead_body = f"    return shared({bias + 10});"

    path.write_text(
        "\n".join(
            [
                f"static volatile int {stem}_bias = {bias};",
                "",
                "__attribute__((noinline)) static int shared(int value)",
                "{",
                f"    return value + {stem}_bias;",
                "}",
                "",
                f"__attribute__((noinline)) int {stem}_live(void)",
                "{",
                live_body,
                "}",
                "",
                f"__attribute__((noinline)) int {stem}_dead(void)",
                "{",
                dead_body,
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def build_same_name_static_case(tmp_path, keep_shared_flags):
    """Build one temporary project and return removed `:shared` config lines."""
    cc = os.environ.get("CC", "gcc")
    if shutil.which(cc) is None:
        pytest.skip(f"{cc} not found")

    stems = ["one", "two", "three"]
    cflags = [
        "-Wall",
        "-O2",
        "-g",
        "-ffunction-sections",
        "-fprofile-arcs",
        "-ftest-coverage",
    ]
    ldflags = [
        "-coverage",
        "-Wl,--gc-sections",
        "-Wl,--print-gc-sections",
    ]

    for index, stem in enumerate(stems, start=1):
        source_path = tmp_path / f"{stem}.c"
        write_same_name_static_source(
            source_path,
            stem,
            keep_shared_flags[index - 1],
            index,
        )
        run_command(
            [cc, *cflags, "-c", source_path.name, "-o", f"{stem}.o"],
            tmp_path,
        )

    main_lines = [
        "int one_live(void);",
        "int two_live(void);",
        "int three_live(void);",
        "",
        "int main(void)",
        "{",
        "    return one_live() + two_live() + three_live();",
        "}",
        "",
    ]
    (tmp_path / "main.c").write_text(
        "\n".join(main_lines),
        encoding="utf-8",
    )
    run_command(
        [cc, *cflags, "-c", "main.c", "-o", "main.o"],
        tmp_path,
    )

    link_result = subprocess.run(
        [
            cc,
            *ldflags,
            "-o",
            "app",
            "main.o",
            "one.o",
            "two.o",
            "three.o",
        ],
        cwd=tmp_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    removed_shared_count = 0
    for line in link_result.stderr.splitlines():
        if ".text.shared" in line:
            removed_shared_count += 1

    output_path = tmp_path / "funcs-removed.cfg"
    script_result = subprocess.run(
        [
            sys.executable,
            str(script_path()),
            "--quiet",
            "-o",
            output_path.name,
        ],
        cwd=tmp_path,
        input=link_result.stderr,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    lines = []
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if line.endswith(":shared"):
            lines.append(line)

    return lines, removed_shared_count, script_result.stderr


def write_same_name_prelink_source(path, stem, keep_shared, bias):
    """Write one source file for a prelink.o same-name-static-local case."""
    if keep_shared:
        live_body = f"    return escape(shared({bias}));"
        # Keep the object alive through one exported function, but do not add a
        # unique dead wrapper. That lets the test isolate the repeated
        # `.text.shared` removals that must be resolved from prelink.o.
        lines = [
            "__attribute__((noinline)) int escape(int);",
            f"static volatile int {stem}_bias = {bias};",
            "",
            "__attribute__((noinline)) static int shared(int value)",
            "{",
            f"    return value + {stem}_bias;",
            "}",
            "",
            f"__attribute__((noinline)) int {stem}_live(void)",
            "{",
            live_body,
            "}",
            "",
        ]
    else:
        live_body = f"    return {bias};"
        dead_body = f"    return escape(shared({bias + 10}));"
        lines = [
            "__attribute__((noinline)) int escape(int);",
            f"static volatile int {stem}_bias = {bias};",
            "",
            "__attribute__((noinline)) static int shared(int value)",
            "{",
            f"    return value + {stem}_bias;",
            "}",
            "",
            f"__attribute__((noinline)) int {stem}_live(void)",
            "{",
            live_body,
            "}",
            "",
            f"__attribute__((noinline)) int {stem}_dead(void)",
            "{",
            dead_body,
            "}",
            "",
        ]

    path.write_text("\n".join(lines), encoding="utf-8")


def build_same_name_static_prelink_case(tmp_path, keep_shared_flags):
    """Build one prelink.o case and return removed `:shared` config lines."""
    cc = os.environ.get("CC", "gcc")
    if shutil.which(cc) is None:
        pytest.skip(f"{cc} not found")

    stems = ["one", "two", "three"]
    cflags = [
        "-Wall",
        "-O2",
        "-g",
        "-fno-inline",
        "-fno-ipa-cp",
        "-fno-ipa-sra",
        "-fno-tree-ccp",
        "-ffunction-sections",
        "-fprofile-arcs",
        "-ftest-coverage",
    ]
    ldflags = [
        "-coverage",
        "-Wl,--gc-sections",
        "-Wl,--print-gc-sections",
    ]

    for index, stem in enumerate(stems, start=1):
        source_path = tmp_path / f"{stem}.c"
        write_same_name_prelink_source(
            source_path,
            stem,
            keep_shared_flags[index - 1],
            index,
        )
        run_command(
            [cc, *cflags, "-c", source_path.name, "-o", f"{stem}.o"],
            tmp_path,
        )

    (tmp_path / "escape.c").write_text(
        "\n".join(
            [
                "__attribute__((noinline)) int escape(int value)",
                "{",
                "    return value;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    run_command(
        [cc, *cflags, "-c", "escape.c", "-o", "escape.o"],
        tmp_path,
    )

    (tmp_path / "main.c").write_text(
        "\n".join(
            [
                "int one_live(void);",
                "int two_live(void);",
                "int three_live(void);",
                "",
                "int main(void)",
                "{",
                "    return one_live() + two_live() + three_live();",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    run_command(
        [cc, *cflags, "-c", "main.c", "-o", "main.o"],
        tmp_path,
    )

    # `--unique=.text.*` keeps same-name local text sections separate inside
    # prelink.o so the final link can report repeated removals of `.text.shared`.
    run_command(
        [
            cc,
            "-r",
            "-Wl,--unique=.text.*",
            "-o",
            "prelink.o",
            "one.o",
            "two.o",
            "three.o",
            "escape.o",
        ],
        tmp_path,
    )

    link_result = subprocess.run(
        [
            cc,
            *ldflags,
            "-o",
            "app",
            "main.o",
            "prelink.o",
        ],
        cwd=tmp_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    removed_shared_count = 0
    for line in link_result.stderr.splitlines():
        if ".text.shared" in line:
            removed_shared_count += 1

    output_path = tmp_path / "funcs-removed.cfg"
    script_result = subprocess.run(
        [
            sys.executable,
            str(script_path()),
            "--quiet",
            "-o",
            output_path.name,
        ],
        cwd=tmp_path,
        input=link_result.stderr,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    lines = []
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if line.endswith(":shared"):
            lines.append(line)

    return lines, removed_shared_count, script_result.stderr


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
        module.RemovalEntry("foo", "lib.o", "foo.constprop.0", is_unlikely=True),
    ]


def test_parse_linker_map_included_members(tmp_path):
    """The linker map parser should extract included archive members."""
    module = load_script_module()

    map_path = tmp_path / "link.map"
    map_path.write_text(
        "\n".join(
            [
                "Archive member included to satisfy reference by file (symbol)",
                "",
                "lib/libfoo.a(foo.o) main.o (foo)",
                "lib/libfoo.a(bar.o) helper.o (bar)",
                "",
                "Linker script and memory map",
            ]
        ),
        encoding="utf-8",
    )

    archive_key = module.normalize_object_path(str(tmp_path / "lib" / "libfoo.a"))
    assert module.parse_linker_map_included_members(str(map_path)) == {
        (archive_key, "foo.o"),
        (archive_key, "bar.o"),
    }


def test_resolve_linker_map_gcno_removals(tmp_path, monkeypatch):
    """Archive members missing from the linker map should become `object:*`."""
    module = load_script_module()

    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    (lib_dir / "foo.o").write_bytes(b"foo")
    (lib_dir / "foo.gcno").write_bytes(b"")
    (lib_dir / "bar.o").write_bytes(b"bar")
    (lib_dir / "bar.gcno").write_bytes(b"")

    subprocess.run(
        ["ar", "rcs", str(lib_dir / "libstuff.a"), "foo.o", "bar.o"],
        check=True,
        cwd=lib_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    map_path = tmp_path / "link.map"
    map_path.write_text(
        "\n".join(
            [
                "Archive member included to satisfy reference by file (symbol)",
                "",
                "lib/libstuff.a(foo.o) main.o (foo)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    lines, warnings = module.resolve_linker_map_gcno_removals(
        str(tmp_path),
        str(map_path),
    )

    assert lines == ["lib/bar.o:*"]
    assert warnings == []


def test_resolve_linker_map_gcno_removals_warns_for_missing_archive(tmp_path, monkeypatch):
    """Map archives that cannot be resolved on disk should raise warnings."""
    module = load_script_module()

    map_path = tmp_path / "link.map"
    map_path.write_text(
        "\n".join(
            [
                "Archive member included to satisfy reference by file (symbol)",
                "",
                "lib/libstuff.a(foo.o) main.o (foo)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    lines, warnings = module.resolve_linker_map_gcno_removals(
        str(tmp_path),
        str(map_path),
    )

    assert lines == []
    archive_key = module.normalize_object_path(str(tmp_path / "lib" / "libstuff.a"))
    assert warnings == [
        f"linker map archive {archive_key} could not be found on disk"
    ]


def test_merge_config_lines_prefers_whole_object_directives():
    """A whole-object removal should override per-function removals."""
    module = load_script_module()

    assert module.merge_config_lines(
        ["foo.o:bar", "bar.o:baz"],
        ["foo.o:*"],
    ) == ["bar.o:baz", "foo.o:*"]


def test_extract_functions_ignores_generated_gcov_wrappers():
    """GCC-generated gcov wrappers should not become gcov removals."""
    module = load_script_module()

    entries = module.extract_functions(
        [
            "ld: removing unused section '.text.startup._sub_I_00100_0' in file "
            "'prelink.o'\n",
            "ld: removing unused section '.text.exit._sub_D_00100_1' in file "
            "'prelink.o'\n",
            "ld: removing unused section '.text.__gcov_init' in file "
            "'prelink.o'\n",
            "ld: removing unused section '.text.__gcov_exit' in file "
            "'prelink.o'\n",
        ],
        False,
    )

    assert entries == [
        module.RemovalEntry("__gcov_init", "prelink.o", "__gcov_init"),
        module.RemovalEntry("__gcov_exit", "prelink.o", "__gcov_exit"),
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

    assert chosen == ["b.o"]
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


@pytest.mark.xfail(
    reason="final DWARF low_pc zero still counts as live code",
    strict=True,
)
def test_parse_dwarf_data_ignores_zero_low_pc_in_final_dwarf(monkeypatch):
    """A final linked DWARF low_pc of zero should not count as live code."""
    module = load_script_module()

    dwarf_lines = [
        "<0><0>: Abbrev Number: 1 (DW_TAG_compile_unit)",
        "    <1>   DW_AT_name        : final.elf",
        "<1><10>: Abbrev Number: 2 (DW_TAG_subprogram)",
        "    <11>   DW_AT_name        : dead_func",
        "    <12>   DW_AT_low_pc      : 0",
        "    <13>   DW_AT_high_pc     : 0x20",
        "<1><20>: Abbrev Number: 2 (DW_TAG_subprogram)",
        "    <21>   DW_AT_name        : live_func",
        "    <22>   DW_AT_low_pc      : 0x1000",
        "    <23>   DW_AT_high_pc     : 0x20",
    ]

    monkeypatch.setattr(module, "iter_readelf", lambda _readelf, _path: dwarf_lines)

    dwarf_data = module.parse_dwarf_data(["final.elf"], "readelf")

    assert ("dead_func", None) not in dwarf_data.final_defined_functions
    assert ("live_func", None) in dwarf_data.final_defined_functions


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


def test_resolve_removed_entries_removes_hot_and_cold_bodies_together(monkeypatch):
    """Hot and cold sibling removals should combine after leaf resolution."""
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
            defaultdict(set, {"foo": {"lib.o"}}),
            defaultdict(set, {"foo": {"lib.o"}}),
            defaultdict(
                lambda: defaultdict(set),
                {
                    "lib.o": defaultdict(
                        set,
                        {
                            "foo": {"foo", "foo.cold"},
                        },
                    ),
                },
            ),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [
            module.RemovalEntry("foo", "prelink.o", "foo"),
            module.RemovalEntry("foo", "prelink.o", "foo", is_unlikely=True),
        ],
        False,
    )

    assert lines == ["lib.o:foo"]
    assert warnings == []
    assert review_lines == []


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


@pytest.mark.xfail(
    reason="same-name locals still resolve too early from survivor hints",
    strict=True,
)
def test_resolve_removed_entries_retries_same_name_after_same_origin_hint(monkeypatch):
    """Retry same-name locals after later same-origin removals resolve cleanly."""
    module = load_script_module()

    gcno_paths = {
        "xen/common/rangeset.o": "xen/common/rangeset.gcno",
        "xen/lib/list-sort.o": "xen/lib/list-sort.gcno",
    }
    monkeypatch.setattr(module, "matching_gcno_path", lambda path: gcno_paths.get(path))
    monkeypatch.setattr(
        module,
        "build_symbol_indexes",
        lambda _root, _names: (
            defaultdict(
                set,
                {
                    "merge": {"xen/common/rangeset.o", "xen/lib/list-sort.o"},
                    "rangeset_merge": {"xen/common/rangeset.o"},
                },
            ),
            defaultdict(
                set,
                {
                    "merge": {"xen/common/rangeset.o", "xen/lib/list-sort.o"},
                    "rangeset_merge": {"xen/common/rangeset.o"},
                },
            ),
            defaultdict(lambda: defaultdict(set)),
        ),
    )

    lines, warnings, review_lines = module.resolve_removed_entries(
        [
            module.RemovalEntry("merge", "prelink.o", "merge"),
            module.RemovalEntry("rangeset_merge", "prelink.o", "rangeset_merge"),
        ],
        False,
        module.DwarfResolutionState(
            {("merge", "xen/common/rangeset.o")},
            set(),
        ),
    )

    assert lines == [
        "xen/common/rangeset.o:rangeset_merge",
        "xen/common/rangeset.o:merge",
    ]
    assert warnings == []
    assert review_lines == []


@pytest.mark.parametrize(
    ("keep_shared_flags", "expected_shared_lines", "expected_removed_count"),
    [
        ((False, False, True), ["one.o:shared", "two.o:shared"], 2),
        ((True, True, True), [], 0),
        ((True, False, True), ["two.o:shared"], 1),
    ],
    ids=[
        "only-one-shared-body-survives",
        "all-shared-bodies-survive",
        "subset-of-shared-bodies-survive",
    ],
)
def test_same_name_static_locals_are_scoped_per_object(
    tmp_path,
    keep_shared_flags,
    expected_shared_lines,
    expected_removed_count,
):
    """Same-name static locals should resolve to each removed leaf object."""
    lines, removed_shared_count, stderr_text = build_same_name_static_case(
        tmp_path,
        keep_shared_flags,
    )

    assert removed_shared_count == expected_removed_count
    assert sorted(lines) == expected_shared_lines
    assert "warning:" not in stderr_text


@pytest.mark.parametrize(
    ("keep_shared_flags", "expected_shared_lines", "expected_removed_count"),
    [
        ((False, False, True), ["one.o:shared", "two.o:shared"], 2),
        ((True, True, True), [], 0),
        ((True, False, True), ["two.o:shared"], 1),
    ],
    ids=[
        "only-one-shared-body-survives",
        "all-shared-bodies-survive",
        "subset-of-shared-bodies-survive",
    ],
)
def test_same_name_static_locals_from_prelink(
    tmp_path,
    keep_shared_flags,
    expected_shared_lines,
    expected_removed_count,
):
    """Incremental links should still scope same-name static removals."""
    lines, removed_shared_count, stderr_text = build_same_name_static_prelink_case(
        tmp_path,
        keep_shared_flags,
    )

    assert removed_shared_count == expected_removed_count
    assert sorted(lines) == expected_shared_lines
    assert "warning:" not in stderr_text


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
