test: test.c
	gcc -Wall -g -fstack-protector-all -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fsanitize=address -fPIE -pie -O2 -fcf-protection=full -Wl,-z,relro,-z,now -o test test.c

clean:
	rm -f test

.PHONY: clean test
