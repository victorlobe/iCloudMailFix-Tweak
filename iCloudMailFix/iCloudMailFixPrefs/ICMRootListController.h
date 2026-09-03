#import <Preferences/PSListController.h>

@interface ICMRootListController : PSListController {
	UIAlertView *_caUpdateAlert;
	NSTimer *_caUpdateTimer;
	NSDate *_caUpdateStarted;
}

- (void)updateCABundle:(id)sender;
- (void)pollCABundleUpdate:(NSTimer *)timer;

@end
