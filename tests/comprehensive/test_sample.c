#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Function that uses stack variables (for canary testing)
void vulnerable_function(const char* input) {
    char buffer[100];
    strcpy(buffer, input);  // Potentially unsafe
    printf("Buffer: %s\n", buffer);
}

// Function that uses printf (for FORTIFY testing) 
void fortify_test() {
    char* user_input = "Hello World";
    printf("%s\n", user_input);
}

// Function that might trigger integer overflow checks
int math_function(int a, int b) {
    return a * b + a;
}

// Function pointer (useful for CFI/PAC testing)
typedef int (*func_ptr_t)(int, int);
func_ptr_t get_math_function() {
    return math_function;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    
    fortify_test();
    
    func_ptr_t fp = get_math_function();
    int result = fp(10, 20);
    printf("Math result: %d\n", result);
    
    return 0;
}