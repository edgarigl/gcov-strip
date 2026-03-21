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

If the linker reports discarded code from an intermediate object that does
not have a matching `*.gcno` file, `ld_gc_sections_to_funcs.py` scans leaf
`*.o` files under the build tree and tries to map each removed name back to
a single object. If that mapping is ambiguous, it prints a warning and
falls back to a commented `# REVIEW ...` entry for human review unless
`--strict-object-match` is used.

The object resolution order is:

1. If the linker-reported object has its own matching `*.gcno`, use it
   directly.
2. Otherwise, if final-ELF DWARF uniquely shows which same-name leaf object
   survived in the linked image, choose the remaining candidate object as the
   removed one.
3. Otherwise scan leaf `*.o` files and find those that define the same
   function name.
4. If exactly one leaf object matches, use it.
5. If several leaf objects match, prefer the one leaf object that also
   appears somewhere in the linker removal set.
6. If resolution is still not unique, emit a commented `# REVIEW ...` entry,
   or fail with `--strict-object-match`.

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

### How the DWARF check works

The DWARF logic uses two different kinds of entries:

- `DW_TAG_subprogram` entries represent normal function DIEs. If a subprogram
  has `DW_AT_low_pc` or `DW_AT_ranges`, the tool treats that as evidence that
  the function still has concrete out-of-line machine code and should not be
  auto-removed as inline-only.
- `DW_TAG_inlined_subroutine` entries represent inline expansions inside a
  caller. The tool follows `DW_AT_abstract_origin` from that entry back to the
  abstract DIE that identifies the callee, then walks upward to the containing
  `DW_TAG_subprogram` to identify the caller that contains the inline expansion.

That lets the tool build:

- a set of functions that still appear to have out-of-line code
- a map of `inline callee -> callers that inline it`

A function is treated as an inline-only removal candidate only when:

- it appears through `DW_TAG_inlined_subroutine` expansions
- it does not appear to have out-of-line code of its own
- every observed caller that inlines it was already removed by the linker
- the callee and callers can be mapped back to concrete leaf objects with
  matching `*.gcno` files

This is intentionally conservative. If the DWARF provenance is missing or
ambiguous, the tool leaves the entry in review-only form instead of widening
the removal scope automatically.

The same compile-unit provenance can also help resolve ambiguous linker
removals. If two leaf objects both define `merge`, but DWARF in the final ELF
shows that the surviving `merge` belongs to only one compile unit, the tool can
scope the removal to the other candidate object without falling back to a
review-only entry.

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

## Object-qualified config format

Generated configs use object-qualified removals:

```
common/bar.o:foo
```

- `common/bar.o:foo` removes `foo` only while rewriting `common/bar.gcno`.

When object resolution is ambiguous or impossible, generated configs now
contain commented review notes instead of an unsafe bare-name fallback:

```
# REVIEW ambiguous removal for merge from prelink.o
# candidates: common/rangeset.o, lib/list-sort.o
# merge
```

## Strict mode

- `ld_gc_sections_to_funcs.py --strict-object-match` fails instead of falling
  back to a commented review entry when a removed symbol cannot be mapped to a
  single leaf object.

## Notes

- The `bar.c` source is intentionally removed by `--gc-sections` to show
  how stripped notes prevent stale coverage entries.
- Generated artifacts like `*.gcno`, `*.gcda`, and `coverage*.html` are
  ignored in `.gitignore`.
