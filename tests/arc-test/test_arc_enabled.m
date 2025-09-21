#import <Foundation/Foundation.h>

// Objective-C code that will use ARC
@interface TestClass : NSObject
@property (strong, nonatomic) NSString *testString;
@end

@implementation TestClass
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        TestClass *obj = [[TestClass alloc] init];
        obj.testString = @"ARC enabled test";
        NSLog(@"%@", obj.testString);
        // ARC will automatically handle memory management
    }
    return 0;
}