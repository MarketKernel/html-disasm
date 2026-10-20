// The sample iOS program the tests open (build.sh): Objective-C classes with instance and class
// methods, a category, NSString literals, selectors, a block, and a call into a Swift framework.
#import <Foundation/Foundation.h>

extern long HelloKitAnswer(long);  // HelloKit.framework, Swift (@_cdecl)

@interface Greeter : NSObject
@property (nonatomic, copy) NSString *name;
- (instancetype)initWithName:(NSString *)name;
- (NSString *)greeting;
+ (Greeter *)defaultGreeter;
@end

@implementation Greeter
- (instancetype)initWithName:(NSString *)name {
  if ((self = [super init])) _name = [name copy];
  return self;
}
- (NSString *)greeting {
  return [NSString stringWithFormat:@"Hello, %@!", self.name];
}
+ (Greeter *)defaultGreeter {
  return [[Greeter alloc] initWithName:@"iOS"];
}
@end

@interface NSString (Shouting)
- (NSString *)shouted;
@end

@implementation NSString (Shouting)
- (NSString *)shouted {
  return [[self uppercaseString] stringByAppendingString:@"!"];
}
@end

int main(int argc, char **argv) {
  @autoreleasepool {
    Greeter *g = [Greeter defaultGreeter];
    NSLog(@"%@ %@ %ld", [g greeting], [@"done" shouted], HelloKitAnswer(argc));
    [[NSArray arrayWithObjects:@"a", @"b", nil] enumerateObjectsUsingBlock:^(id obj, NSUInteger i, BOOL *stop) {
      NSLog(@"%lu %@", (unsigned long)i, obj);
    }];
  }
  return 0;
}
