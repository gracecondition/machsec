#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void unsafe_strcpy_test() {
    char buffer[10];
    char source[] = "This is a long string that should trigger FORTIFY_SOURCE";
    
    // This should trigger FORTIFY_SOURCE protection when compiled with -D_FORTIFY_SOURCE=2
    strcpy(buffer, source);
    printf("Copied: %s\n", buffer);
}

int main() {
    printf("Testing FORTIFY_SOURCE protection\n");
    
    char buffer[20];
    char input[] = "Hello World";
    
    // Safe operations that should work
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Safe copy: %s\n", buffer);
    
    // Allocate some memory to test heap functions
    void *ptr1 = malloc(100);
    void *ptr2 = malloc(200);
    
    if (ptr1 && ptr2) {
        printf("Memory allocated successfully\n");
        free(ptr1);
        free(ptr2);
    }
    
    return 0;
}