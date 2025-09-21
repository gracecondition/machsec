#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Function to trigger stack canary and fortify
void vulnerable_function() {
    char buffer[64];
    char *input = "This is a test string that might be long";
    
    // This will use fortified strcpy if available
    strcpy(buffer, input);
    
    // This will use fortified sprintf if available  
    sprintf(buffer, "Test: %s", input);
    
    printf("Buffer: %s\n", buffer);
}

// Function to potentially trigger UBSan
void ubsan_test() {
    int arr[5] = {1, 2, 3, 4, 5};
    volatile int index = 10; // Out of bounds but compiler might optimize
    
    // Potential undefined behavior
    int *ptr = NULL;
    if (ptr) {
        *ptr = 42;
    }
    
    // Integer overflow
    int big = 2000000000;
    volatile int result = big + big;
    
    printf("Result: %d\n", result);
}

int main() {
    printf("Testing security mitigations\n");
    vulnerable_function();
    ubsan_test();
    return 0;
}
