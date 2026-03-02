#CROSS=$(HOME)/dev/bin/microblazeel-xilinx-elf-
CC=$(CROSS)gcc-14
GCOV=gcov-14
GCOVR=gcovr --gcov-executable $(GCOV)

CFLAGS = -Wall -O2 -g
CFLAGS += -ffunction-sections -fdump-tree-all -fdump-ipa-all -dumpdir ./dumps/
CFLAGS += -fprofile-arcs -ftest-coverage
#CFLAGS += -fkeep-static-functions
LDFLAGS += -coverage
LDFLAGS += -Wl,--gc-sections -Wl,--print-gc-sections
TARGET = ctest
OBJS = ctest.o foo.o bar.o

ASFLAGS = -static -nostdlib -nostartfiles

all: $(TARGET)

$(OBJS): Makefile

$(TARGET): $(OBJS)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@ 2>&1 | ./ld_gc_sections_to_funcs.py -o funcs-removed.cfg
	./gcov-strip -c funcs-removed.cfg --verbose --list-lines

run: $(TARGET)
	./$(TARGET)
	$(GCOVR) --html-details coverage.html --html-self-contained --decisions
	$(GCOVR)

clean:
	$(RM) dumps/*
	$(RM) $(OBJS) $(TARGET)
