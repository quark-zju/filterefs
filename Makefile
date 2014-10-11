CC=gcc
LD=gcc
CFLAGS?=-Wall -O2
#-DNDEBUG
PREFIX?=/usr/local
GIT_VERSION:=$(shell [ -e .git ] && git describe --abbrev=4 --tags --always --dirty)

.PHONY: all clean install

filterefs: utils/debug.o config.o main.o
	$(LD) -o $@ -lfuse -pthread $^

main.o: main.c
	$(CC) -c -o $@ $(CFLAGS) -pthread -DFREFS_GIT_VERSION=\"$(GIT_VERSION)\" -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse $<

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) -pthread -D_FILE_OFFSET_BITS=64 $^

clean:
	-rm -f *.o **/*.o filterefs

install: filterefs
	install -D -m0755 -oroot -groot -s $< $(PREFIX)/bin/filterefs
