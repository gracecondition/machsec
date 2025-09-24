#include <stdio.h>
#include <string.h>

// Test function that uses stack
void test_stack_function() {
    char stack_buffer[1024];
    strcpy(stack_buffer, "Testing NX stack protection");
    printf("%s\n", stack_buffer);
}

int main() {
    printf("Testing NX stack protection\n");
    test_stack_function();
    return 0;
}