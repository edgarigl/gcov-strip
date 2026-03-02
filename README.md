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
- `gcov-strip` reads that config and removes those function records from
  any `*.gcno` files under the build directory.
- `gcovr` uses the updated `gcno` files to produce the coverage report.

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

Use `--dry-run` to report removals without modifying `*.gcno` files.

## Notes

- The `bar.c` source is intentionally removed by `--gc-sections` to show
  how stripped notes prevent stale coverage entries.
- Generated artifacts like `*.gcno`, `*.gcda`, and `coverage*.html` are
  ignored in `.gitignore`.
