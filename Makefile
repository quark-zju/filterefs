CC=gcc
LD=gcc
CFLAGS?=-Wall -O2 -DNDEBUG
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

# only root can use -o dev and -o allow_other, which is useful for filterefs.
# filterefs passes fstat as is, so it's probably okay.
install: filterefs
	install -D -m6755 -oroot -groot -s $< $(PREFIX)/bin/filterefs
