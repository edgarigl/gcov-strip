#CROSS=$(HOME)/dev/bin/microblazeel-xilinx-elf-
CC ?= $(CROSS)gcc
GCOV ?= gcov
READELF ?= readelf
SHELL := /bin/bash

EXAMPLE_DIR := examples/minimal
TARGET := ctest
GCC_VERSIONS ?= 9 10 11 12 13 14 15 16 17 18 19 20
BINUTILS_VERSIONS ?= 2.26 2.30 2.34 2.42 2.43.1 2.44 2.45 2.46.0
READELF_VARIANTS ?= g gno-strict-dwarf 2 3 4 5 5-gno-strict-dwarf 5-gdwarf64 5-gdwarf64-gno-strict-dwarf
READELF_MATRIX_LOG ?= tests/cache/check-readelf-matrix.log

.PHONY: all $(TARGET) run test check check-gcc-matrix check-static-lib-gcc-matrix check-readelf-matrix check-all clean distclean help

all:
	$(MAKE) -C $(EXAMPLE_DIR) ROOT=$(CURDIR) all

$(TARGET):
	$(MAKE) -C $(EXAMPLE_DIR) ROOT=$(CURDIR) $(TARGET)

run:
	$(MAKE) -C $(EXAMPLE_DIR) ROOT=$(CURDIR) run

test:
	pytest -q

check:
	pylint gcov-strip ld-gc-sections-to-funcs
	$(MAKE) test

check-gcc-matrix:
	@for v in $(GCC_VERSIONS); do \
		if ! command -v gcc-$$v >/dev/null 2>&1 || \
		   ! command -v gcov-$$v >/dev/null 2>&1; then \
			continue; \
		fi; \
		$(MAKE) clean >/dev/null && \
		CC=gcc-$$v GCOV=gcov-$$v $(MAKE) run || exit 1; \
	done

check-static-lib-gcc-matrix:
	@for v in $(GCC_VERSIONS); do \
		if ! command -v gcc-$$v >/dev/null 2>&1 || \
		   ! command -v gcov-$$v >/dev/null 2>&1; then \
			continue; \
		fi; \
		$(MAKE) -C examples/static-lib ROOT=$(CURDIR) clean >/dev/null && \
		CC=gcc-$$v GCOV=gcov-$$v $(MAKE) -C examples/static-lib ROOT=$(CURDIR) demo || exit 1; \
	done

check-readelf-matrix:
	@mkdir -p $(dir $(READELF_MATRIX_LOG))
	@set -o pipefail; \
	GCC_VERSIONS="$(GCC_VERSIONS)" \
	BINUTILS_VERSIONS="$(BINUTILS_VERSIONS)" \
	VARIANTS="$(READELF_VARIANTS)" \
	BASELINE_READELF="$(READELF)" \
	tests/check-readelf-matrix.sh 2>&1 | tee "$(READELF_MATRIX_LOG)"

check-all: check check-gcc-matrix check-readelf-matrix check-static-lib-gcc-matrix

help:
	@printf '%s\n' \
		"Targets:" \
		"  make run                  Build and run examples/minimal" \
		"  make test                 Run pytest regression tests" \
		"  make check                Run pylint and pytest" \
		"  make check-gcc-matrix     Run the GCC coverage matrix" \
		"  make check-static-lib-gcc-matrix Run the static-lib GCC matrix" \
		"  make check-readelf-matrix Run the GCC/DWARF/readelf matrix" \
		"  make check-all            Run all checks" \
		"  make clean                Remove example build output and caches" \
		"  make distclean            Also remove cached binutils downloads"

clean:
	$(MAKE) -C $(EXAMPLE_DIR) ROOT=$(CURDIR) clean
	$(RM) -r dumps
	$(RM) -r tests/cache/build
	$(RM) funcs-removed.cfg
	$(RM) *.gcda *.gcno *.gcov coverage*.html

distclean: clean
	$(RM) -r tests/cache/binutils tests/cache/src
