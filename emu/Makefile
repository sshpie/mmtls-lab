CC      = gcc
CFLAGS  = -O2 -g -Wall -Wextra -Wno-unused-parameter \
          -I src -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpthread

SRCS    = src/arm64.c   \
          src/mem.c     \
          src/mmu.c     \
          src/dev_uart.c \
          src/dev_gic.c \
          src/dev_virtio.c \
          src/dtb.c     \
          src/ctrl.c    \
          src/machine.c \
          src/emu.c

OBJS    = $(SRCS:.c=.o)
TARGET  = emu64

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
