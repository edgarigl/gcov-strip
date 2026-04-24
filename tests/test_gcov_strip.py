"""Regression tests for gcov-strip."""

import argparse
import os
import struct
import subprocess
import sys
from collections import defaultdict
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest


def load_script_module():
    """Load the executable script as an importable module for testing."""
    script_path = Path(__file__).resolve().parents[1] / "gcov-strip"
    loader = SourceFileLoader("gcov_strip", str(script_path))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def repo_root():
    """Return the repository root that holds the standalone scripts."""
    return Path(__file__).resolve().parents[1]


def fixtures_dir():
    """Return the committed test fixture directory."""
    return repo_root() / "tests" / "fixtures"


def encode_gcov_string(value, use_word_counts):
    """Encode one gcov string field for the selected layout."""
    raw = value.encode("utf-8") + b"\x00"
    if use_word_counts:
        raw = raw.ljust((len(raw) + 3) & ~3, b"\x00")
        return struct.pack("<I", len(raw) // 4) + raw
    return struct.pack("<I", len(raw)) + raw


def encode_record(tag, payload, use_word_counts):
    """Build one gcno record header plus payload."""
    length = len(payload) // 4 if use_word_counts else len(payload)
    return struct.pack("<II", tag, length) + payload


def build_line_payload(filename, line_numbers, use_word_counts):
    """Build one tiny `GCOV_TAG_LINES` payload for testing."""
    payload = bytearray(struct.pack("<I", 0))
    payload.extend(struct.pack("<I", 0))
    payload.extend(encode_gcov_string(filename, use_word_counts))
    for line_number in line_numbers:
        payload.extend(struct.pack("<I", line_number))
    payload.extend(struct.pack("<I", 0))
    payload.extend(encode_gcov_string("", use_word_counts))
    return bytes(payload)


def build_function_payload(name, use_word_counts):
    """Build one tiny `GCOV_TAG_FUNCTION` payload for testing."""
    return b"\x00" * 12 + encode_gcov_string(name, use_word_counts)


def build_old_gcno(records):
    """Build one synthetic old-layout gcno file."""
    return build_gcno(records, True)


def build_gcno(records, use_word_counts):
    """Build one synthetic gcno file for the selected record-length layout."""
    cwd = b"/tmp"
    cwd = cwd + b"\x00"
    if use_word_counts:
        cwd = cwd.ljust((len(cwd) + 3) & ~3, b"\x00")

    data = bytearray()
    data.extend(b"oncg")
    data.extend(b"*51B" if use_word_counts else b"*24B")
    data.extend(b"\x00" * (4 if use_word_counts else 8))
    if use_word_counts:
        data.extend(struct.pack("<I", len(cwd) // 4))
    else:
        data.extend(struct.pack("<I", len(cwd)))
    data.extend(cwd)
    data.extend(struct.pack("<I", 1))
    for tag, payload in records:
        data.extend(encode_record(tag, payload, use_word_counts))
    return bytes(data)


def test_parse_config_entry_requires_object_scoped_entries():
    """Config entries must be `object:function` pairs."""
    module = load_script_module()

    assert module.parse_config_entry("dir/foo.o:bar") == ("dir/foo.o", "bar")
    assert module.parse_config_entry("dir/foo.o:*") == ("dir/foo.o", "*")
    with pytest.raises(ValueError):
        module.parse_config_entry("bar")
    with pytest.raises(ValueError):
        module.parse_config_entry(":bar")
    with pytest.raises(ValueError):
        module.parse_config_entry("foo.o:")


def test_select_gcno_layout_supports_known_versions_and_newer_byte_layout(capsys):
    """Known versions pick the right layout, and newer unknown versions warn."""
    module = load_script_module()

    old_data = b"oncg*51B" + b"\x00" * 8
    new_data = b"oncg*24B" + b"\x00" * 8
    future_data = b"oncg*15B" + b"\x00" * 8

    assert module.select_gcno_layout(old_data) is True
    assert module.select_gcno_layout(new_data) is False
    assert module.select_gcno_layout(future_data) is False
    assert "assuming byte-count layout" in capsys.readouterr().err

    with pytest.raises(ValueError):
        module.select_gcno_layout(b"bad!" + b"*24B" + b"\x00" * 8)


def test_select_gcno_layout_rejects_older_unknown_versions():
    """Unknown versions older than the byte-count baseline should still fail."""
    module = load_script_module()

    with pytest.raises(ValueError, match=r"unsupported gcno version B23\*"):
        module.select_gcno_layout(b"oncg*32B" + b"\x00" * 8)


def test_string_and_record_helpers_handle_old_and_new_layouts():
    """String, function, and line parsing should work for both layouts."""
    module = load_script_module()

    for use_word_counts in (True, False):
        encoded = encode_gcov_string("foo", use_word_counts)
        assert module.read_gcov_string(encoded, 0, use_word_counts) == ("foo", len(encoded))
        assert module.parse_function_name(
            build_function_payload("bar", use_word_counts), use_word_counts
        ) == "bar"
        assert module.parse_line_record(
            build_line_payload("file.c", [10, 12], use_word_counts),
            use_word_counts,
        ) == {"file.c": {10, 12}}

    with pytest.raises(ValueError):
        module.read_gcov_string(b"\x01\x00\x00", 0, False)
    with pytest.raises(ValueError):
        module.read_gcov_string(b"\x04\x00\x00\x00a", 0, False)


def test_rebuild_gcno_keeps_word_count_record_lengths():
    """Partial rewrites of old gcno files must keep record lengths in words."""
    module = load_script_module()

    foo_payload = build_function_payload("foo", True)
    foo_lines = build_line_payload("foo.c", [1], True)
    bar_payload = build_function_payload("bar", True)
    bar_lines = build_line_payload("bar.c", [2], True)
    data = build_old_gcno(
        [
            (module.GCOV_TAG_FUNCTION, foo_payload),
            (module.GCOV_TAG_LINES, foo_lines),
            (module.GCOV_TAG_FUNCTION, bar_payload),
            (module.GCOV_TAG_LINES, bar_lines),
        ]
    )

    updated, removed, removed_names, removed_lines = module.rebuild_gcno(
        data,
        {"bar"},
        list_lines=True,
    )

    assert removed == 1
    assert removed_names == ["bar"]
    assert removed_lines == [("bar", {"bar.c": {2}})]

    use_word_counts = module.select_gcno_layout(updated)
    assert use_word_counts is True
    start = module.record_start_offset(updated, use_word_counts)
    first_tag, first_length = struct.unpack_from("<II", updated, start)
    assert first_tag == module.GCOV_TAG_FUNCTION
    assert first_length == len(foo_payload) // 4

    records = list(module.iter_gcno_records(updated, start, use_word_counts))
    assert [module.parse_function_name(payload, True) for tag, payload in records if tag == module.GCOV_TAG_FUNCTION] == ["foo"]


def test_count_gcno_functions_counts_function_records_in_both_layouts():
    """Whole-file removal accounting should count gcno function records."""
    module = load_script_module()

    for use_word_counts in (True, False):
        data = build_gcno(
            [
                (module.GCOV_TAG_FUNCTION, build_function_payload("foo", use_word_counts)),
                (module.GCOV_TAG_LINES, build_line_payload("foo.c", [1], use_word_counts)),
                (module.GCOV_TAG_FUNCTION, build_function_payload("bar", use_word_counts)),
            ],
            use_word_counts,
        )
        assert module.count_gcno_functions(data) == 2


def test_load_config_ignores_comments_and_normalizes_paths(tmp_path):
    """Config loading should skip comments and fold equivalent object paths."""
    module = load_script_module()

    config_path = tmp_path / "funcs.cfg"
    config_path.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "dir/../foo.o:bar",
                "foo.o:baz",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert module.load_config(str(config_path)) == {"foo.o": {"bar", "baz"}}


def test_process_file_dry_run_preserves_byte_count_gcno(tmp_path):
    """Dry runs should report removals without rewriting newer gcno layouts."""
    module = load_script_module()

    foo_payload = build_function_payload("foo", False)
    foo_lines = build_line_payload("foo.c", [1], False)
    bar_payload = build_function_payload("bar", False)
    bar_lines = build_line_payload("bar.c", [2], False)
    original = build_gcno(
        [
            (module.GCOV_TAG_FUNCTION, foo_payload),
            (module.GCOV_TAG_LINES, foo_lines),
            (module.GCOV_TAG_FUNCTION, bar_payload),
            (module.GCOV_TAG_LINES, bar_lines),
        ],
        False,
    )
    gcno_path = tmp_path / "foo.gcno"
    gcno_path.write_bytes(original)

    changed, removed, removed_names, removed_lines = module.process_file(
        str(gcno_path),
        {"bar"},
        list_lines=True,
        dry_run=True,
    )

    assert changed is True
    assert removed == 1
    assert removed_names == ["bar"]
    assert removed_lines == [("bar", {"bar.c": {2}})]
    assert gcno_path.read_bytes() == original


def test_handle_gcno_file_skips_unrelated_gcno(tmp_path, monkeypatch):
    """Unrelated gcno files should be skipped without touching process_file."""
    module = load_script_module()

    gcno_path = tmp_path / "foo.gcno"
    gcno_path.write_bytes(b"")
    args = argparse.Namespace(list_lines=False, dry_run=False, verbose=False)

    monkeypatch.setattr(
        module,
        "process_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected call")),
    )

    changed, removed = module.handle_gcno_file(
        str(gcno_path),
        args,
        defaultdict(set, {"bar.o": {"baz"}}),
    )

    assert (changed, removed) == (0, 0)


def test_handle_gcno_file_reports_verbose_and_lines(monkeypatch, capsys):
    """Verbose and line-list reporting should flow through one gcno handler."""
    module = load_script_module()
    args = argparse.Namespace(list_lines=True, dry_run=True, verbose=True)

    monkeypatch.setattr(module, "gcno_object_paths", lambda _path: {"foo.o"})
    monkeypatch.setattr(
        module,
        "process_file",
        lambda *_args, **_kwargs: (
            True,
            1,
            ["bar"],
            [("bar", {"bar.c": {7}})],
        ),
    )
    monkeypatch.setattr(
        module,
        "print_removed_lines",
        lambda path, removed_lines: print(f"lines {path} {removed_lines}"),
    )

    changed, removed = module.handle_gcno_file(
        "foo.gcno",
        args,
        defaultdict(set, {"foo.o": {"bar"}}),
    )

    assert (changed, removed) == (1, 1)
    captured = capsys.readouterr()
    assert "removed bar from foo.gcno" in captured.out
    assert "lines foo.gcno [('bar', {'bar.c': {7}})]" in captured.out

def test_handle_gcno_file_removes_whole_gcno(tmp_path, capsys):
    """A config entry with `*` should remove the whole gcno file."""
    module = load_script_module()

    gcno_path = tmp_path / "foo.gcno"
    gcno_path.write_bytes(
        build_gcno(
            [
                (module.GCOV_TAG_FUNCTION, build_function_payload("foo", False)),
                (module.GCOV_TAG_FUNCTION, build_function_payload("bar", False)),
            ],
            False,
        )
    )
    args = argparse.Namespace(list_lines=False, dry_run=False, verbose=True)

    changed, removed = module.handle_gcno_file(
        str(gcno_path),
        args,
        defaultdict(set, {"foo.o": {"*"}}),
    )

    assert (changed, removed) == (1, 2)
    assert gcno_path.exists() is False
    assert "removed whole gcno" in capsys.readouterr().out
def test_main_rewrites_matching_gcno_file(tmp_path, monkeypatch, capsys):
    """Main should rewrite one matching gcno file from an on-disk config."""
    module = load_script_module()

    gcno_path = tmp_path / "foo.gcno"
    config_path = tmp_path / "funcs.cfg"
    original = build_gcno(
        [
            (module.GCOV_TAG_FUNCTION, build_function_payload("foo", False)),
            (module.GCOV_TAG_LINES, build_line_payload("foo.c", [1], False)),
            (module.GCOV_TAG_FUNCTION, build_function_payload("bar", False)),
            (module.GCOV_TAG_LINES, build_line_payload("bar.c", [2], False)),
        ],
        False,
    )
    gcno_path.write_bytes(original)
    config_path.write_text("foo.o:bar\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    assert module.main(["-c", str(config_path)]) == 0
    assert gcno_path.read_bytes() != original

    use_word_counts = module.select_gcno_layout(gcno_path.read_bytes())
    start = module.record_start_offset(gcno_path.read_bytes(), use_word_counts)
    records = list(module.iter_gcno_records(gcno_path.read_bytes(), start, use_word_counts))
    assert [
        module.parse_function_name(payload, use_word_counts)
        for tag, payload in records
        if tag == module.GCOV_TAG_FUNCTION
    ] == ["foo"]
    assert "Processed 1 file(s); removed 1 function record(s)." in capsys.readouterr().out

def test_main_removes_whole_gcno_file_from_object_wide_entry(tmp_path, monkeypatch, capsys):
    """Main should honor `object:*` config entries by deleting whole gcno files."""
    module = load_script_module()

    gcno_path = tmp_path / "foo.gcno"
    config_path = tmp_path / "funcs.cfg"
    gcno_path.write_bytes(
        build_gcno(
            [
                (module.GCOV_TAG_FUNCTION, build_function_payload("foo", False)),
                (module.GCOV_TAG_FUNCTION, build_function_payload("bar", False)),
            ],
            False,
        )
    )
    config_path.write_text("foo.o:*\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    assert module.main(["-c", str(config_path), "-v"]) == 0
    assert gcno_path.exists() is False
    captured = capsys.readouterr()
    assert "removed whole gcno" in captured.out
    assert "Processed 1 file(s); removed 2 function record(s)." in captured.out
def test_example_minimal_funcs_removed_matches_golden():
    """The minimal example should keep producing the reviewed removal config."""
    root = repo_root()
    expected = (
        fixtures_dir()
        / "example-minimal"
        / "funcs-removed.cfg.expected"
    ).read_text(encoding="utf-8")

    subprocess.run(
        ["make", "clean"],
        check=True,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        ["make", "ctest"],
        check=True,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    actual = (root / "examples" / "minimal" / "funcs-removed.cfg").read_text(
        encoding="utf-8"
    )

    assert actual == expected


def test_example_static_lib_funcs_removed_matches_golden():
    """The static-lib example should emit whole-object removals from the map."""
    root = repo_root()
    expected = (
        fixtures_dir()
        / "example-static-lib"
        / "funcs-removed.cfg.expected"
    ).read_text(encoding="utf-8")

    subprocess.run(
        ["make", "-C", "examples/static-lib", "clean"],
        check=True,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        ["make", "-C", "examples/static-lib", "demo"],
        check=True,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    config_path = root / "examples" / "static-lib" / "funcs-removed.cfg"
    assert config_path.read_text(encoding="utf-8") == expected
    assert (root / "examples" / "static-lib" / "bar.gcno").exists() is False


def test_local_pip_install_exposes_public_script_names(tmp_path):
    """A local pip install should expose the standalone script entry points."""
    venv_dir = tmp_path / "venv"
    env = dict(os.environ)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

    subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
        check=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    venv_python = venv_dir / "bin" / "python"
    venv_pip = venv_dir / "bin" / "pip"
    gcov_strip = venv_dir / "bin" / "gcov-strip"
    ld_tool = venv_dir / "bin" / "ld-gc-sections-to-funcs"

    subprocess.run(
        [str(venv_pip), "install", "--no-build-isolation", str(repo_root())],
        check=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    assert gcov_strip.exists()
    assert ld_tool.exists()

    gcov_help = subprocess.run(
        [str(gcov_strip), "--help"],
        check=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    ld_help = subprocess.run(
        [str(ld_tool), "--help"],
        check=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    assert "Remove selected function records" in gcov_help.stdout
    assert "Extract removed function names" in ld_help.stdout
    assert venv_python.exists()
