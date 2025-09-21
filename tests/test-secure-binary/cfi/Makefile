test: test.c
	clang -Wall -g -fstack-protector-all -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fsanitize=address -fsanitize=cfi -flto -fvisibility=hidden -fPIE -pie -O2 -Wl,-z,relro,-z,now -o test test.c

clean:
	rm -f test

.PHONY: clean test
