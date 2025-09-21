#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

int vulnerable_large_alloca(size_t size) {
    char *buffer = alloca(size);
    buffer[0] = 'A';
    return buffer[0];
}

int main() {
    printf("Testing stack clash protection\n");
    vulnerable_large_alloca(8192);
    return 0;
}