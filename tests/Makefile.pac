CC = clang
CFLAGS_PAC = -arch arm64e -mbranch-protection=pac-ret
CFLAGS_NO_PAC = -arch arm64 -fno-stack-protector

all: pac_enabled pac_disabled

pac_enabled: pac_test.c
	$(CC) $(CFLAGS_PAC) -o pac_enabled pac_test.c

pac_disabled: pac_test.c
	$(CC) $(CFLAGS_NO_PAC) -o pac_disabled pac_test.c

clean:
	rm -f pac_enabled pac_disabled

.PHONY: all clean