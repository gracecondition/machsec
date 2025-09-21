CC = /usr/bin/clang
CFLAGS_BASE = -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

all: test_system

test_system: test_system.c
	$(CC) $(CFLAGS_BASE) -o test_system test_system.c

clean:
	rm -f test_system

.PHONY: all clean