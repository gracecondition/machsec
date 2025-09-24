#include <stdio.h>
#include <stdlib.h>

// Test binary for NX heap protection
int main() {
    printf("Testing NX heap protection\n");
    
    // Allocate some heap memory
    char *heap_buffer = malloc(1024);
    if (heap_buffer) {
        snprintf(heap_buffer, 1024, "Heap allocation test");
        printf("%s\n", heap_buffer);
        free(heap_buffer);
    }
    
    return 0;
}