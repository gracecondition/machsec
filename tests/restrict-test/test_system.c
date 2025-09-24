#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

// Binary that uses system calls that might be restricted
int main() {
    printf("Testing system restrictions\n");
    
    // Try to use some system functions that might be restricted
    uid_t uid = getuid();
    printf("UID: %d\n", uid);
    
    return 0;
}