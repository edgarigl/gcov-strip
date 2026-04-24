#CROSS=$(HOME)/dev/bin/microblazeel-xilinx-elf-
CC ?= $(CROSS)gcc
GCOV ?= gcov
GCOVR = gcovr --gcov-executable $(GCOV)
READELF ?= readelf
ROOT ?= $(abspath ../..)
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

all: $(TARGET)

.PHONY: all run clean

$(OBJS): Makefile

$(TARGET): $(OBJS)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@ 2>&1 | \
		$(ROOT)/gcov-find-removals --readelf "$(READELF)" -o funcs-removed.cfg
	$(ROOT)/gcov-strip -c funcs-removed.cfg --verbose --list-lines

run: $(TARGET)
	./$(TARGET)
	$(GCOVR) --html-details coverage.html --html-self-contained --decisions
	$(GCOVR) > coverage.txt
	grep -q 'ctest.c' coverage.txt
	grep -q 'foo.c' coverage.txt
	! grep -q 'bar.c' coverage.txt
	cat coverage.txt

clean:
	$(RM) funcs-removed.cfg
	$(RM) $(OBJS) $(TARGET)
	$(RM) *.gcda *.gcno *.gcov coverage*.html coverage.txt
