#import <Foundation/Foundation.h>
#import "ICMCreditsController.h"

@implementation ICMCreditsController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Credits" target:self];
	}
	return _specifiers;
}

@end
