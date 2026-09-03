#import <Foundation/Foundation.h>
#import "ICMInstructionsController.h"

@implementation ICMInstructionsController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Instructions" target:self];
	}
	return _specifiers;
}

@end
