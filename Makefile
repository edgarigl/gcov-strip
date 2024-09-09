#CROSS=$(HOME)/dev/bin/microblazeel-xilinx-elf-
CFLAGS = -Wall -O2
TARGET = ctest

CC=$(CROSS)gcc

all: $(TARGET)

clean:
	$(RM) $(TARGET)

