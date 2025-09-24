#import <Foundation/Foundation.h>

// Objective-C code compiled without ARC (manual memory management)
@interface TestClass : NSObject {
    NSString *testString;
}
- (void)setTestString:(NSString *)str;
- (NSString *)testString;
@end

@implementation TestClass
- (void)setTestString:(NSString *)str {
    [testString release];
    testString = [str retain];
}

- (NSString *)testString {
    return testString;
}

- (void)dealloc {
    [testString release];
    [super dealloc];
}
@end

int main(int argc, const char * argv[]) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    TestClass *obj = [[TestClass alloc] init];
    [obj setTestString:@"Manual memory management test"];
    NSLog(@"%@", [obj testString]);
    [obj release];
    
    [pool release];
    return 0;
}