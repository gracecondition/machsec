CC=gcc
SECURE_FLAGS=-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-all
BASIC_FLAGS=-O2

all: test test_secure

test: test.c
	$(CC) $(BASIC_FLAGS) -o $@ $<

test_secure: test.c
	$(CC) $(SECURE_FLAGS) -o $@ $<

clean:
	rm -f test test_secure

.PHONY: all clean