#include <stdio.h>
#include <limits.h>

int add_with_overflow_check(int a, int b) {
    int result;
    if (__builtin_add_overflow(a, b, &result)) {
        printf("Integer overflow detected!\n");
        return -1;
    }
    return result;
}

int multiply_with_overflow_check(long long a, long long b) {
    long long result;
    if (__builtin_mul_overflow(a, b, &result)) {
        printf("Multiplication overflow detected!\n");
        return -1;
    }
    return result;
}

int main() {
    printf("Testing integer overflow protection\n");
    
    int sum = add_with_overflow_check(INT_MAX, 1);
    printf("Sum result: %d\n", sum);
    
    long long product = multiply_with_overflow_check(LLONG_MAX, 2);
    printf("Product result: %lld\n", product);
    
    return 0;
}