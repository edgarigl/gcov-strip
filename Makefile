#CROSS=$(HOME)/dev/bin/microblazeel-xilinx-elf-
CC ?= $(CROSS)gcc
GCOV ?= gcov
GCOVR=gcovr --gcov-executable $(GCOV)

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

ASFLAGS = -static -nostdlib -nostartfiles

all: $(TARGET)

$(OBJS): Makefile

$(TARGET): $(OBJS)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@ 2>&1 | ./ld-gc-sections-to-funcs -o funcs-removed.cfg
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
	for v in 9 10 11 12 13 14; do \
		$(MAKE) clean >/dev/null && \
		CC=gcc-$$v GCOV=gcov-$$v $(MAKE) run || exit 1; \
	done

check-all: check check-gcc-matrix

clean:
	$(RM) -r dumps
	$(RM) funcs-removed.cfg
	$(RM) $(OBJS) $(TARGET)
	$(RM) *.gcda *.gcno *.gcov coverage*.html
