# gcov-strip example

`gcov-strip` is a small helper that strips `gcno` notes for selected
functions so coverage reports stay in sync with functions removed by
`--gc-sections` garbage collection during linking.

This repo contains a minimal example project that:

- builds a tiny C binary with coverage flags
- uses the linker map to list discarded functions
- runs `gcov-strip` to remove their notes
- generates an HTML coverage report with `gcovr`

## How it works

- `ld_gc_sections_to_funcs.py` parses the linker output and writes
  `funcs-removed.cfg` with functions removed by garbage collection.
  When possible it writes `object:function` entries so removals are scoped
  to the matching `*.gcno` file instead of applying globally by name.
- `gcov-strip` reads that config and removes those function records from
  any `*.gcno` files under the build directory.
- `gcovr` uses the updated `gcno` files to produce the coverage report.

If the linker reports discarded code from an aggregate object such as
`prelink.o` or `built_in.o`, `ld_gc_sections_to_funcs.py` scans leaf `*.o`
files under the build tree and tries to map each removed name back to a
single object. If that mapping is ambiguous, it prints a warning and falls
back to a commented `# REVIEW ...` entry for human review unless
`--strict-object-match` is used.

If the linker drops inline-only functions, `ld_gc_sections_to_funcs.py` can
scan DWARF info to detect them using `--dwarf`:

```
./ld_gc_sections_to_funcs.py -o funcs-removed.cfg --dwarf ctest
```

Provide multiple `--dwarf` paths to scan several binaries or objects.

### Why DWARF scanning can be needed

GCC emits `*.gcno` notes after early inlining but before some late inlining
passes. If a helper survives long enough to be instrumented, it can get its own
`GCOV_TAG_FUNCTION` record even if the compiler later inlines it and removes the
out-of-line body. In that case the linker log only reports the caller, so the
inline-only callee remains in the `gcno` file unless `--dwarf` is used to
discover the inlining relationship.

## gcno notes overview

`*.gcno` files contain coverage notes emitted at compile time. They record
the control-flow graph for each function, including basic blocks, arcs
(directed edges between blocks), and line tables that map blocks back to
source line numbers. Runtime coverage data is stored separately in `*.gcda`
files, which hold counters for those blocks/arcs. The `gcov-strip` tool only
rewrites the `gcno` notes so coverage reports do not reference functions that
the linker discarded.

## Example workflow

Build, run, and regenerate coverage output:

```
make clean && make run
```

The `make` step already runs `gcov-strip` and prints any removed source
lines. `make run` executes the binary and writes `coverage.html`.

## gcov-strip usage

Strip functions listed in `funcs-removed.cfg` and print removed lines:

```
./gcov-strip -c funcs-removed.cfg --list-lines
```

Use multiple `-c` options to combine several config files, and `--dry-run`
to report removals without modifying `*.gcno` files.

Use `--require-object-match` to ignore legacy bare-name entries and only
apply object-qualified removals to the corresponding `*.gcno` file.

## Object-qualified config format

Generated configs may contain either of these line formats:

```
foo
common/bar.o:foo
```

- `foo` is the legacy global form and removes `foo` from any matching
  `*.gcno` file. `gcov-strip` still accepts it for backward compatibility.
- `common/bar.o:foo` removes `foo` only while rewriting `common/bar.gcno`.

When object resolution is ambiguous or impossible, generated configs now
contain commented review notes instead of an unsafe bare-name fallback:

```
# REVIEW ambiguous removal for merge from prelink.o
# candidates: common/rangeset.o, lib/list-sort.o
# merge
```

## Strict modes

- `ld_gc_sections_to_funcs.py --strict-object-match` fails instead of falling
  back to a commented review entry when a removed symbol cannot be mapped to a
  single leaf object.
- `gcov-strip --require-object-match` ignores legacy bare-name config entries
  and only applies object-qualified entries to matching `*.gcno` files.

## Notes

- The `bar.c` source is intentionally removed by `--gc-sections` to show
  how stripped notes prevent stale coverage entries.
- Generated artifacts like `*.gcno`, `*.gcda`, and `coverage*.html` are
  ignored in `.gitignore`.
