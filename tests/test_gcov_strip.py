"""Regression tests for gcov-strip."""

import struct
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
    cwd = b"/tmp"
    cwd = cwd + b"\x00"
    cwd = cwd.ljust((len(cwd) + 3) & ~3, b"\x00")
    data = bytearray()
    data.extend(b"oncg")
    data.extend(b"*51B")
    data.extend(b"\x00" * 4)
    data.extend(struct.pack("<I", len(cwd) // 4))
    data.extend(cwd)
    data.extend(struct.pack("<I", 1))
    for tag, payload in records:
        data.extend(encode_record(tag, payload, True))
    return bytes(data)


def test_parse_config_entry_requires_object_scoped_entries():
    """Config entries must be `object:function` pairs."""
    module = load_script_module()

    assert module.parse_config_entry("dir/foo.o:bar") == ("dir/foo.o", "bar")
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
