#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

int main() {
    printf("Testing heap cookies/hardening\n");
    
    void *ptr1 = malloc(100);
    void *ptr2 = malloc(200);
    
    printf("Allocated memory at %p and %p\n", ptr1, ptr2);
    printf("Usable size: %zu\n", malloc_usable_size(ptr1));
    
    free(ptr1);
    free(ptr2);
    
    return 0;
}