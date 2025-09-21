CC = /usr/bin/clang
CFLAGS_BASE = -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

all: test_nx

test_nx: test_nx.c
	$(CC) $(CFLAGS_BASE) -o test_nx test_nx.c

clean:
	rm -f test_nx

.PHONY: all clean