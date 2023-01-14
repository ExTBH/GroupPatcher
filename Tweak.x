#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "Fishhook/fishhook.h"

#define GROUPS @[\
	@"group.com.facebook.family", \
	@"group.com.facebook.Messenger", \
	@"group.com.facebook.LightSpeed"\
]

#define KEYCHAIN_GROUPS @[\
	@"T84QZS65DQ.platformFamily" \
]


%hook NSFileManager
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier{
	if ([GROUPS containsObject:groupIdentifier] == NO){
		return %orig;
	}

	NSString *sandboxedContainer = [NSHomeDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/%@", groupIdentifier]];

	NSFileManager *sharedManager = NSFileManager.defaultManager;
	BOOL isDir = YES;
	if ([sharedManager fileExistsAtPath:sandboxedContainer isDirectory:&isDir]){
		return [NSURL fileURLWithPath:sandboxedContainer isDirectory:YES];
	}
	else {
		[sharedManager createDirectoryAtPath:sandboxedContainer withIntermediateDirectories:NO attributes:nil error:nil];
		return [NSURL fileURLWithPath:sandboxedContainer isDirectory:YES];
	}
}

%end


%hook NSUserDefaults
- (instancetype)initWithSuiteName:(NSString *)suitename{
	return %orig([@"gp." stringByAppendingString:suitename]);
}

%end

%hook NSHTTPCookieStorage
+ (NSHTTPCookieStorage *)sharedCookieStorageForGroupContainerIdentifier:(NSString *)identifier{
	return [self sharedHTTPCookieStorage];
}
%end

#pragma mark Keychain Redirecting

@interface FBBaseKeychainStore : NSObject

@end

%hook FBBaseKeychainStore
- (void)create:(id)arg1 data:(id)arg2 onSuccess:(id)arg3 onError:(id)arg4 withTargetQueue:(id)arg5{
	NSLog(@"GroupPatcher FBBase: arg1(%@) arg2(%@)", arg1, arg2);
	%orig;
}
%end

%ctor{
	NSLog(@"GroupPatcher FBBase");
}