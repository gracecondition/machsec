CC = /usr/bin/clang
CFLAGS_BASE = -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

# Note: Real iOS App Store encryption happens during App Store processing
# We can only test unencrypted binaries in our test environment
all: test_plain

test_plain: test_plain.c
	$(CC) $(CFLAGS_BASE) -o test_plain test_plain.c

clean:
	rm -f test_plain

.PHONY: all clean