#CROSS=$(HOME)/dev/bin/microblazeel-xilinx-elf-
CC ?= $(CROSS)gcc
GCOV ?= gcov
GCOVR=gcovr --gcov-executable $(GCOV)
READELF ?= readelf
SHELL := /bin/bash

CFLAGS = -Wall -O2 -g
CFLAGS += -ffunction-sections
#CFLAGS += -fdump-tree-all -fdump-ipa-all -dumpdir ./dumps/
CFLAGS += -fprofile-arcs -ftest-coverage
#CFLAGS += -fkeep-static-functions
#CFLAGS += -fkeep-inline-functions
#CFLAGS += -fno-inline
LDFLAGS += -coverage
LDFLAGS += -Wl,--gc-sections -Wl,--print-gc-sections
TARGET = ctest
OBJS = ctest.o foo.o bar.o
GCC_VERSIONS ?= 9 10 11 12 13 14 15 16 17 18 19 20
BINUTILS_VERSIONS ?= 2.26 2.30 2.34 2.42 2.43.1 2.44 2.45 2.46.0
READELF_VARIANTS ?= g gno-strict-dwarf 2 3 4 5 5-gno-strict-dwarf 5-gdwarf64 5-gdwarf64-gno-strict-dwarf
READELF_MATRIX_LOG ?= tests/cache/check-readelf-matrix.log

ASFLAGS = -static -nostdlib -nostartfiles

all: $(TARGET)

$(OBJS): Makefile

$(TARGET): $(OBJS)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@ 2>&1 | \
		./ld-gc-sections-to-funcs --readelf "$(READELF)" -o funcs-removed.cfg
	./gcov-strip -c funcs-removed.cfg --verbose --list-lines

run: $(TARGET)
	./$(TARGET)
	$(GCOVR) --html-details coverage.html --html-self-contained --decisions
	$(GCOVR)

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

check-readelf-matrix:
	@mkdir -p $(dir $(READELF_MATRIX_LOG))
	@set -o pipefail; \
	GCC_VERSIONS="$(GCC_VERSIONS)" \
	BINUTILS_VERSIONS="$(BINUTILS_VERSIONS)" \
	VARIANTS="$(READELF_VARIANTS)" \
	BASELINE_READELF="$(READELF)" \
	tests/check-readelf-matrix.sh 2>&1 | tee "$(READELF_MATRIX_LOG)"

check-all: check check-gcc-matrix check-readelf-matrix

clean:
	$(RM) -r dumps
	$(RM) -r tests/cache/build
	$(RM) funcs-removed.cfg
	$(RM) $(OBJS) $(TARGET)
	$(RM) *.gcda *.gcno *.gcov coverage*.html

distclean: clean
	$(RM) -r tests/cache/binutils tests/cache/src
