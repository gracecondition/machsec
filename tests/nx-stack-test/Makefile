CC = /usr/bin/clang
CFLAGS_BASE = -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

all: test_stack

test_stack: test_stack.c
	$(CC) $(CFLAGS_BASE) -o test_stack test_stack.c

clean:
	rm -f test_stack

.PHONY: all clean