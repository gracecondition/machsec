#include <stdio.h>
#include <stdlib.h>

// Simple function that uses pointer authentication
// This will generate PAC instructions on ARM64 with PAC enabled
__attribute__((noinline))
int authenticated_function(int (*func_ptr)(int), int value) {
    // Call through authenticated function pointer
    return func_ptr(value);
}

int test_function(int x) {
    return x * 2 + 1;
}

int main() {
    int (*ptr)(int) = test_function;
    int result = authenticated_function(ptr, 42);
    printf("Result: %d\n", result);
    return 0;
}