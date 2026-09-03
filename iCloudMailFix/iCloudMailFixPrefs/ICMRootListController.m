#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "ICMRootListController.h"

static NSString * const kCAUpdateRequestPath = @"/var/mobile/Library/Preferences/com.victorlobe.icloudmailfix-ca-update";
static NSString * const kCAUpdateStatusPath = @"/var/mobile/Library/Preferences/com.victorlobe.icloudmailfix-ca-update-status";
static NSString * const kCAOverrideBundlePath = @"/Library/iCloudMailFix/cacert.override.pem";
static NSString * const kCADefaultBundlePath = @"/Library/iCloudMailFix/cacert.pem";

@implementation ICMRootListController

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
	UITableViewCell *cell = [super tableView:tableView cellForRowAtIndexPath:indexPath];
	if (indexPath.section != 0 || indexPath.row != 0) return cell;

	cell.textLabel.hidden = YES;
	cell.detailTextLabel.hidden = YES;
	cell.selectionStyle = UITableViewCellSelectionStyleNone;
	cell.backgroundColor = [UIColor clearColor];
	cell.backgroundView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
	cell.selectedBackgroundView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
	cell.contentView.backgroundColor = [UIColor clearColor];

	NSString *iconPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"headerIcon" ofType:@"png"];
	UIImageView *iconView = [[UIImageView alloc] initWithFrame:CGRectMake(0, 12.0, 96.0, 96.0)];
	iconView.tag = 1984;
	iconView.image = iconPath ? [UIImage imageWithContentsOfFile:iconPath] : nil;
	iconView.contentMode = UIViewContentModeScaleAspectFit;
	iconView.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
	iconView.center = CGPointMake(cell.contentView.bounds.size.width / 2.0, 60.0);
	[cell.contentView addSubview:iconView];

	UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(0, 112.0, cell.contentView.bounds.size.width, 24.0)];
	label.tag = 1985;
	label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
	label.text = @"iCloudMailFix";
	label.textAlignment = NSTextAlignmentCenter;
	label.font = [UIFont boldSystemFontOfSize:17.0];
	label.textColor = [UIColor darkTextColor];
	label.backgroundColor = [UIColor clearColor];
	[cell.contentView addSubview:label];
	return cell;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
	if (indexPath.section == 0 && indexPath.row == 0) return 148.0;
	return [super tableView:tableView heightForRowAtIndexPath:indexPath];
}

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
		[self refreshCABundleDate];
	}

	return _specifiers;
}

- (void)refreshCABundleDate {
	NSString *path = [[NSFileManager defaultManager] fileExistsAtPath:kCAOverrideBundlePath] ?
		kCAOverrideBundlePath : kCADefaultBundlePath;
	NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
	NSString *date = nil;
	for (NSString *line in [contents componentsSeparatedByString:@"\n"]) {
		NSString *prefix = @"## Certificate data from Mozilla as of: ";
		if ([line hasPrefix:prefix]) {
			date = [line substringFromIndex:prefix.length];
			break;
		}
	}
	if (!date.length) date = @"Unknown";
	NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:NULL];
	NSDate *modified = [attributes objectForKey:NSFileModificationDate];
	NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
	[formatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"]];
	[formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
	NSString *lastUpdated = modified ? [formatter stringFromDate:modified] : @"Unknown";
	for (id specifier in _specifiers) {
		if ([[specifier propertyForKey:@"label"] isEqualToString:@"Certificate Settings"]) {
			[specifier setProperty:[NSString stringWithFormat:@"Last updated: %@\nMozilla bundle date: %@", lastUpdated, date]
				forKey:@"footerText"];
			break;
		}
	}
}

- (void)updateCABundle:(id)sender {
	(void)sender;
	[_caUpdateTimer invalidate];
	[[NSFileManager defaultManager] removeItemAtPath:kCAUpdateStatusPath error:NULL];
	NSData *request = [NSData dataWithBytes:"update\n" length:7];
	BOOL ok = [request writeToFile:kCAUpdateRequestPath options:NSDataWritingAtomic error:NULL];
	if (!ok) {
		UIAlertView *result = [[UIAlertView alloc] initWithTitle:@"iCloud Mail Fix"
			message:@"The update could not be requested." delegate:nil
			cancelButtonTitle:@"OK" otherButtonTitles:nil];
		[result show];
		return;
	}

	_caUpdateAlert = [[UIAlertView alloc] initWithTitle:@"iCloud Mail Fix"
		message:@"Updating CA certificate bundle …" delegate:nil cancelButtonTitle:nil otherButtonTitles:nil];
	[_caUpdateAlert show];
	_caUpdateStarted = [NSDate date];
	_caUpdateTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self
		selector:@selector(pollCABundleUpdate:) userInfo:nil repeats:YES];
}

- (void)pollCABundleUpdate:(NSTimer *)timer {
	(void)timer;
	NSString *status = [NSString stringWithContentsOfFile:kCAUpdateStatusPath
		encoding:NSUTF8StringEncoding error:NULL];
	BOOL timedOut = _caUpdateStarted && -[_caUpdateStarted timeIntervalSinceNow] > 120.0;
	if ((!status || [status rangeOfString:@"pending" options:NSCaseInsensitiveSearch].location != NSNotFound) && !timedOut) return;

	[_caUpdateTimer invalidate];
	_caUpdateTimer = nil;
	[_caUpdateAlert dismissWithClickedButtonIndex:0 animated:YES];
	_caUpdateAlert = nil;
	NSString *message = [status rangeOfString:@"success" options:NSCaseInsensitiveSearch].location != NSNotFound ?
		@"The CA certificate bundle was updated successfully." :
		@"The CA certificate bundle could not be updated. The previous bundle remains active.";
	if (timedOut && !status) message = @"The CA bundle update timed out. The previous bundle remains active.";
	if ([status rangeOfString:@"success" options:NSCaseInsensitiveSearch].location != NSNotFound) {
		[self refreshCABundleDate];
		[self reloadSpecifiers];
	}
	UIAlertView *result = [[UIAlertView alloc] initWithTitle:@"iCloud Mail Fix"
		message:message delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];
	[result show];
}

@end
