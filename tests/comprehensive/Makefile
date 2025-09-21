CC = /usr/bin/clang
CFLAGS_BASE = -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

# Build one binary with maximum security features enabled
SECURE_FLAGS = -fstack-protector-all -fPIE -pie -O2 -D_FORTIFY_SOURCE=2 -arch arm64e -mbranch-protection=pac-ret

# Build one binary with security features disabled where possible
INSECURE_FLAGS = -fno-stack-protector -fno-pie -no-pie -O0 -U_FORTIFY_SOURCE -arch arm64

all: test_secure test_insecure

test_secure: test_sample.c
	$(CC) $(CFLAGS_BASE) $(SECURE_FLAGS) -o test_secure test_sample.c

test_insecure: test_sample.c
	$(CC) $(CFLAGS_BASE) $(INSECURE_FLAGS) -o test_insecure test_sample.c

clean:
	rm -f test_secure test_insecure

.PHONY: all clean