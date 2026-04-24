CC ?= gcc
AR ?= ar
GCOV ?= gcov
GCOVR = gcovr --gcov-executable $(GCOV)
READELF ?= readelf
ROOT ?= $(abspath ../..)
SHELL := /bin/bash

CFLAGS = -Wall -O2 -g
CFLAGS += -ffunction-sections
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -coverage
LDFLAGS += -Wl,--gc-sections -Wl,--print-gc-sections
LDFLAGS += -Wl,-Map=link.map
TARGET = app
LIB = libstuff.a
LIBOBJS = foo.o bar.o

all: $(TARGET)

.PHONY: all demo clean

$(LIBOBJS): Makefile
main.o: Makefile

$(LIB): $(LIBOBJS)
	$(AR) rcs $@ $^

$(TARGET): main.o $(LIB)
	$(LINK.o) main.o $(LIB) -o $@ 2> link.log
	$(ROOT)/ld-gc-sections-to-funcs \
		--quiet \
		--linker-map link.map \
		-o funcs-removed.cfg < link.log
	$(ROOT)/gcov-strip -c funcs-removed.cfg --verbose

demo: $(TARGET)
	./$(TARGET)
	$(GCOVR)

clean:
	$(RM) link.log link.map funcs-removed.cfg
	$(RM) $(LIB) $(LIBOBJS) main.o $(TARGET)
	$(RM) *.gcda *.gcno *.gcov coverage*.html
