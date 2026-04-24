# gcov-strip example

`gcov-strip` is a small helper that strips `gcno` notes for selected
functions so coverage reports stay in sync with functions removed by
`--gc-sections` garbage collection during linking.

This repo contains a minimal example project that:

- builds a tiny C binary with coverage flags
- uses linker `--print-gc-sections` output to list discarded functions
- runs `gcov-strip` to remove their notes
- generates an HTML coverage report with `gcovr`

The example sources and generated build artifacts live under
`examples/minimal/`.

An additional static-library example lives under `examples/static-lib/`.

## How it works

- `gcov-find-removals` parses the linker output and writes
  `funcs-removed.cfg` with object-qualified removals from garbage collection.
  When possible it writes `object:function` entries so removals are scoped
  to the matching `*.gcno` file instead of applying globally by name.
- With `--linker-map`, `gcov-find-removals` can also emit whole-object
  removals for archive members that were never linked into the final image.
- `gcov-strip` reads that config and removes those function records from
  any `*.gcno` files under the build directory.
- `gcovr` uses the updated `gcno` files to produce the coverage report.

If the linker reports discarded code from an intermediate object that does
not have a matching `*.gcno` file, `gcov-find-removals` scans leaf
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

If the linker drops inline-only functions, `gcov-find-removals` can
scan DWARF info to detect them using `--dwarf`:

```bash
./gcov-find-removals \
  -o examples/minimal/funcs-removed.cfg \
  --dwarf examples/minimal/ctest
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

The root `make` wrapper builds `examples/minimal/`, runs `gcov-strip`,
and writes coverage output there.

## Install

The tools can be installed directly from a git URL while keeping the current
command names:

```bash
pip install git+https://github.com/edgarigl/gcov-strip
```

Developer mode:

```bash
git clone https://github.com/edgarigl/gcov-strip
cd gcov-strip
pip install -e .
```

This packaging keeps `gcov-strip` and `gcov-find-removals` as standalone
single-file scripts in the repo, so they can still be copied out and run
directly.

## Testing

The repo has three main test entry points:

- `make check` runs `pylint` plus the `pytest` suite. The pytest suite covers
  script regression tests, a local `pip` install smoke test, and a committed
  golden-output check for `examples/minimal/funcs-removed.cfg`.
- `make check-gcc-matrix` runs the example end-to-end with each installed
  `gcc-X` / `gcov-X` pair from `GCC_VERSIONS`.
- `make check-static-lib-gcc-matrix` runs the static-library example across
  the installed `gcc-X` / `gcov-X` pairs and exercises the linker-map based
  whole-object gcno pruning path.
- `make check-readelf-matrix` runs the broader DWARF/readelf matrix. It tests
  each installed GCC across the configured DWARF flag variants and compares the
  generated `funcs-removed.cfg` across the selected binutils `readelf`
  versions.

The pytest suite runs directly from the source tree; it does not require
`pip install -e .`.

The readelf matrix writes:

- `tests/cache/check-readelf-matrix.log` with the full run log
- `tests/cache/check-readelf-matrix.csv` with per-case status rows

and prints a compact terminal summary showing:

- `ok` / `skip` / `fail` per `gcc + DWARF variant`
- the exercised readelf/binutils versions and how many matrix cases each one
  covered

Use `make help` to list the common targets.

## gcov-strip usage

Strip functions listed in `funcs-removed.cfg` and print removed lines:

```bash
./gcov-strip -c examples/minimal/funcs-removed.cfg --list-lines
```

Use multiple `-c` options to combine several config files, and `--dry-run`
to report removals without modifying `*.gcno` files.

Whole-object removals use the same config file format:

```txt
lib/bar.o:*
```

That removes the whole matching `lib/bar.gcno` file instead of stripping
individual function records from it.

## Object-qualified config format

Generated configs use object-qualified removals:

```
common/bar.o:foo
```

- `common/bar.o:foo` removes `foo` only while rewriting `common/bar.gcno`.
- `common/bar.o:*` removes the whole `common/bar.gcno` file.

`gcov-find-removals --linker-map` can generate `object:*` entries for
static-library members that have matching `*.gcno` files but were never
linked into the final image.

When object resolution is ambiguous or impossible, generated configs now
contain commented review notes instead of an unsafe bare-name fallback:

```
# REVIEW ambiguous removal for merge from prelink.o
# candidates: common/rangeset.o, lib/list-sort.o
# merge
```

If a removed symbol only matches leaf objects without `*.gcno` files and there
is no non-assembler DWARF function provenance for it, the tool tags it
separately as likely non-covered code, for example hand-written assembly.
Assembler DWARF does not block this classification:

```txt
# INFO likely assembly/no-coverage removal for foo from arch/head.o
# reason: no gcno coverage
# candidates: arch/head.o
# foo

```

## Strict mode

- `gcov-find-removals --strict-object-match` fails instead of falling
  back to a commented review entry when a removed symbol cannot be mapped to a
  single leaf object.

## Notes

- The `bar.c` source is intentionally removed by `--gc-sections` to show
  how stripped notes prevent stale coverage entries.
- Generated artifacts like `*.gcno`, `*.gcda`, and `coverage*.html` are
  ignored in `.gitignore`.
