"""Regression tests for the diff-oriented style checker."""

import subprocess
import sys
from pathlib import Path


def repo_root():
    """Return the repository root that holds the checker script."""
    return Path(__file__).resolve().parents[1]


def checkpatch_path():
    """Return the diff-oriented style checker path."""
    return repo_root() / "scripts" / "checkpatch"


def run_checkpatch(tmp_path, filename, source, diff_text):
    """Write one file plus diff and run checkpatch in that directory."""
    file_path = tmp_path / filename
    diff_path = tmp_path / "change.diff"
    file_path.write_text(source, encoding="utf-8")
    diff_path.write_text(diff_text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(checkpatch_path()), "--diff", str(diff_path)],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def test_checkpatch_allows_simple_changed_python(tmp_path):
    """A straightforward changed Python file should pass."""
    result = run_checkpatch(
        tmp_path,
        "simple.py",
        "\n".join(
            [
                "def helper():",
                "    value = 1",
                "    return value",
                "",
            ]
        ),
        "\n".join(
            [
                "--- a/simple.py",
                "+++ b/simple.py",
                "@@ -0,0 +1,3 @@",
                "+def helper():",
                "+    value = 1",
                "+    return value",
                "",
            ]
        ),
    )

    assert result.returncode == 0
    assert result.stderr == ""


def test_checkpatch_flags_top_level_definition_without_blank_line(tmp_path):
    """Top-level defs should be separated by a blank line."""
    result = run_checkpatch(
        tmp_path,
        "spacing.py",
        "\n".join(
            [
                "def first():",
                "    return 1",
                "def second():",
                "    return 2",
                "",
            ]
        ),
        "\n".join(
            [
                "--- a/spacing.py",
                "+++ b/spacing.py",
                "@@ -1,2 +1,4 @@",
                " def first():",
                "     return 1",
                "+def second():",
                "+    return 2",
                "",
            ]
        ),
    )

    assert result.returncode == 1
    assert "CSTYLE001" in result.stderr
    assert "@@ -1,4 +1,4 @@" in result.stderr
    assert "+def second():" in result.stderr
    assert "     return 1" in result.stderr


def test_checkpatch_flags_lambda_on_changed_line(tmp_path):
    """Lambdas on changed lines should be reported."""
    result = run_checkpatch(
        tmp_path,
        "lambda_case.py",
        "\n".join(
            [
                "def build():",
                "    func = lambda value: value + 1",
                "    return func",
                "",
            ]
        ),
        "\n".join(
            [
                "--- a/lambda_case.py",
                "+++ b/lambda_case.py",
                "@@ -0,0 +1,3 @@",
                "+def build():",
                "+    func = lambda value: value + 1",
                "+    return func",
                "",
            ]
        ),
    )

    assert result.returncode == 1
    assert "CSTYLE002" in result.stderr
    assert "+    func = lambda value: value + 1" in result.stderr


def test_checkpatch_flags_complex_comprehension_on_changed_line(tmp_path):
    """Generator expressions and filtered comprehensions should be reported."""
    result = run_checkpatch(
        tmp_path,
        "comp_case.py",
        "\n".join(
            [
                "def build(values):",
                "    result = sorted(value for value in values if value)",
                "    return result",
                "",
            ]
        ),
        "\n".join(
            [
                "--- a/comp_case.py",
                "+++ b/comp_case.py",
                "@@ -0,0 +1,3 @@",
                "+def build(values):",
                "+    result = sorted(value for value in values if value)",
                "+    return result",
                "",
            ]
        ),
    )

    assert result.returncode == 1
    assert "CSTYLE003" in result.stderr
    assert "+    result = sorted(value for value in values if value)" in result.stderr


def test_checkpatch_builds_diff_for_single_commit(monkeypatch):
    """A positional commit should expand to commit^..commit."""
    calls = []

    def fake_check_output(args, **_kwargs):
        calls.append(args)
        if args[:3] == ["git", "rev-list", "--reverse"]:
            return "abc123\n"
        if args[:3] == ["git", "rev-parse", "abc123^"]:
            return "deadbeef\n"
        if args[:4] == ["git", "show", "-s", "--format=%s"]:
            return "Subject line\n"
        if args[:3] == ["git", "rev-parse", "--short"]:
            return "abc123\n"
        return ""

    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader

    loader = SourceFileLoader("checkpatch", str(checkpatch_path()))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)

    monkeypatch.setattr(module.subprocess, "check_output", fake_check_output)

    diff_inputs = module.load_diff_inputs(module.parse_args(["abc123"]))

    assert diff_inputs == [module.DiffInput("abc123 Subject line", "")]
    assert calls == [
        ["git", "rev-list", "--reverse", "abc123^..abc123"],
        ["git", "rev-parse", "abc123^"],
        ["git", "diff", "--unified=0", "deadbeef..abc123"],
        ["git", "rev-parse", "--short", "abc123"],
        ["git", "show", "-s", "--format=%s", "abc123"],
    ]


def test_checkpatch_keeps_explicit_revision_range(monkeypatch):
    """A positional revision range should be passed through unchanged."""
    calls = []

    def fake_check_output(args, **_kwargs):
        calls.append(args)
        if args[:3] == ["git", "rev-list", "--reverse"]:
            return "abc123\nfed456\n"
        if args[:3] == ["git", "rev-parse", "abc123^"]:
            return "base123\n"
        if args[:3] == ["git", "rev-parse", "fed456^"]:
            return "base456\n"
        if args[:3] == ["git", "rev-parse", "--short"]:
            return f"{args[3]}\n"
        if args[:4] == ["git", "show", "-s", "--format=%s"]:
            return f"subject {args[4]}\n"
        return ""

    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader

    loader = SourceFileLoader("checkpatch", str(checkpatch_path()))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)

    monkeypatch.setattr(module.subprocess, "check_output", fake_check_output)

    diff_inputs = module.load_diff_inputs(module.parse_args(["origin/master..HEAD"]))

    assert diff_inputs == [
        module.DiffInput("abc123 subject abc123", ""),
        module.DiffInput("fed456 subject fed456", ""),
    ]
    assert calls == [
        ["git", "rev-list", "--reverse", "origin/master..HEAD"],
        ["git", "rev-parse", "abc123^"],
        ["git", "diff", "--unified=0", "base123..abc123"],
        ["git", "rev-parse", "--short", "abc123"],
        ["git", "show", "-s", "--format=%s", "abc123"],
        ["git", "rev-parse", "fed456^"],
        ["git", "diff", "--unified=0", "base456..fed456"],
        ["git", "rev-parse", "--short", "fed456"],
        ["git", "show", "-s", "--format=%s", "fed456"],
    ]
