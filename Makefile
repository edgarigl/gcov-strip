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

check-dwarf-matrix:
	for gcc_v in 9 10 11 12 13 14; do \
		for dwarf_v in 2 3 4 5; do \
			echo "== gcc-$$gcc_v -gdwarf-$$dwarf_v =="; \
			$(MAKE) clean >/dev/null; \
			if ! CC=gcc-$$gcc_v GCOV=gcov-$$gcc_v \
				CFLAGS="$(CFLAGS) -gdwarf-$$dwarf_v" \
				$(MAKE) run >/tmp/check-dwarf-$$gcc_v-$$dwarf_v.log 2>&1; then \
				if grep -Eq "unrecognized .*gdwarf|dwarf version .*is not supported|unknown DWARF version" \
					/tmp/check-dwarf-$$gcc_v-$$dwarf_v.log; then \
					echo "skip gcc-$$gcc_v -gdwarf-$$dwarf_v"; \
					continue; \
				fi; \
				cat /tmp/check-dwarf-$$gcc_v-$$dwarf_v.log; \
				exit 1; \
			fi; \
		done; \
	done

check-dwarf-consistency:
	for gcc_v in 9 10 11 12 13 14; do \
		base_cfg=/tmp/funcs-removed-gcc-$$gcc_v-dwarf-5.cfg; \
		echo "== gcc-$$gcc_v dwarf consistency =="; \
		$(MAKE) clean >/dev/null; \
		CC=gcc-$$gcc_v GCOV=gcov-$$gcc_v \
			CFLAGS="$(CFLAGS) -gdwarf-5" \
			$(MAKE) $(TARGET) >/tmp/check-dwarf-consistency-$$gcc_v-5.log 2>&1 || { \
			cat /tmp/check-dwarf-consistency-$$gcc_v-5.log; \
			exit 1; \
		}; \
		cp funcs-removed.cfg $$base_cfg; \
		for variant in g gno-strict-dwarf 2 3 4 5-gno-strict-dwarf; do \
			cfg=/tmp/funcs-removed-gcc-$$gcc_v-dwarf-$$variant.cfg; \
			case "$$variant" in \
				g) \
					variant_flags="$(CFLAGS)"; \
					variant_name="-g"; \
					;; \
				gno-strict-dwarf) \
					variant_flags="$(CFLAGS) -gno-strict-dwarf"; \
					variant_name="-g -gno-strict-dwarf"; \
					;; \
				5-gno-strict-dwarf) \
					variant_flags="$(CFLAGS) -gdwarf-5 -gno-strict-dwarf"; \
					variant_name="-gdwarf-5 -gno-strict-dwarf"; \
					;; \
				*) \
					variant_flags="$(CFLAGS) -gdwarf-$$variant"; \
					variant_name="-gdwarf-$$variant"; \
					;; \
			esac; \
			$(MAKE) clean >/dev/null; \
			CC=gcc-$$gcc_v GCOV=gcov-$$gcc_v \
				CFLAGS="$$variant_flags" \
				$(MAKE) $(TARGET) >/tmp/check-dwarf-consistency-$$gcc_v-$$variant.log 2>&1 || { \
				cat /tmp/check-dwarf-consistency-$$gcc_v-$$variant.log; \
				exit 1; \
			}; \
			cp funcs-removed.cfg $$cfg; \
			if ! diff -u $$base_cfg $$cfg; then \
				echo "DWARF config mismatch for gcc-$$gcc_v: -gdwarf-5 vs $$variant_name"; \
				exit 1; \
			fi; \
		done; \
	done

check-all: check check-gcc-matrix check-dwarf-matrix check-dwarf-consistency

clean:
	$(RM) -r dumps
	$(RM) funcs-removed.cfg
	$(RM) $(OBJS) $(TARGET)
	$(RM) *.gcda *.gcno *.gcov coverage*.html
