#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <substrate.h>
#import "Fishhook/fishhook.h"
#include <mach-o/dyld.h>
#import "EntitlementsForImage/EntitlementsForImage.h"

#define GROUPS @[\
	@"group.com.facebook.family", \
	@"group.com.facebook.Messenger", \
	@"group.com.facebook.LightSpeed", \
    @"T84QZS65DQ.platformFamily" \
]

#define KEYCHAIN_GROUPS @[\
	@"T84QZS65DQ.platformFamily" \
]

static BOOL stringInGroups(NSString *string){
    return [GROUPS containsObject:string];
}
static NSString *keychainPrefix;



// -[NSFileManager containerURLForSecurityApplicationGroupIdentifier:]
static NSURL *(*orig_NSFileManager_container)(id, SEL, id);
/*
    To go around apps using app groups we create containing directories
    in the app sandbox for each group.
*/
static NSURL *override_NSFileManager_container(id self, SEL _cmd, NSString *groupIdentifier){

	// if (stringInGroups(groupIdentifier) == NO){
	// 	return orig_NSFileManager_container(self, _cmd, groupIdentifier);
	// }

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

// -[NSUserDefaaults initWithSuiteName:]
static NSUserDefaults *(*orig_NSUserDefaults_suit)(id, SEL, id);
/*
    Same as above hook.
*/
static NSUserDefaults *override_NSUserDefaults_suit(id self, SEL _cmd, NSString *suit){
    if(stringInGroups(suit)){
        suit = [@"gp." stringByAppendingString:suit];
    }
    return orig_NSUserDefaults_suit(self, _cmd, suit);
}

// +[NSHTTPCookieStorage sharedCookieStorageForGroupContainerIdentifier:]
static NSHTTPCookieStorage *(*orig_NSHTTPCookieStorage_container)(id, SEL, id);
static NSHTTPCookieStorage *override_NSHTTPCookieStorage_container(NSHTTPCookieStorage *self, SEL _cmd, NSString *identifier){
    if(stringInGroups(identifier)){
        return NSHTTPCookieStorage.sharedHTTPCookieStorage;
    }
    return orig_NSHTTPCookieStorage_container(self, _cmd, identifier);
}

#pragma mark Keychain Hooks

static CFDictionaryRef patchAttributes(CFDictionaryRef attributes){
    return attributes;
    CFTypeRef rawRet = nil;
	if(CFDictionaryGetValueIfPresent(attributes, kSecAttrAccessGroup, &rawRet) == true){
        NSString *origAccessGroup = (__bridge NSString*)(CFStringRef)rawRet;
        // to not break FLEX
        if ([origAccessGroup isEqualToString:keychainPrefix]) { return attributes; }
        // Update Access Group
        CFMutableDictionaryRef mutableAttrs = CFDictionaryCreateMutableCopy(NULL, 0, attributes);
        CFDictionaryReplaceValue(mutableAttrs, kSecAttrAccessGroup, (CFStringRef)keychainPrefix);
        
        // Update Account Name
        rawRet = nil;
        if(CFDictionaryGetValueIfPresent(attributes, kSecAttrAccount, &rawRet)){
            NSString *origAccount = (__bridge NSString*)(CFStringRef)rawRet;
            NSString *newAccount = [origAccount stringByAppendingFormat:@"_%@", origAccessGroup];
            CFDictionaryReplaceValue(mutableAttrs, kSecAttrAccount, (CFStringRef)newAccount);
        }
        // Update Service
        if(CFDictionaryGetValueIfPresent(attributes, kSecAttrService, &rawRet)){
            NSString *origService = (__bridge NSString*)(CFStringRef)rawRet;
            NSString *newService = [origService stringByAppendingFormat:@"_%@", origAccessGroup];
            CFDictionaryReplaceValue(mutableAttrs, kSecAttrService, (CFStringRef)newService);
        }

        attributes = mutableAttrs;
	}
	return attributes;
}



static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef  _Nullable *result);
static OSStatus override_SecItemAdd(CFDictionaryRef attributes, CFTypeRef  _Nullable *result){
    
	CFDictionaryRef uattributes = patchAttributes(attributes);
    
	OSStatus status = orig_SecItemAdd(uattributes, result);
    
    NSLog(@"GroupPatcher Logger: Begin Adding Item (%@) to (%@) with response (%i)", attributes, uattributes, (int)status);

    return status;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus override_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate){
	CFDictionaryRef uquery = patchAttributes(query);

    OSStatus status = orig_SecItemUpdate(query, attributesToUpdate);;

    NSLog(@"GroupPatcher Logger: Begin Updating Items (%@) to (%@) with response (%i)", query, uquery, (int)status);

	return status;
}

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
static OSStatus override_SecItemDelete(CFDictionaryRef query){
    // NSLog(@"GroupPatcher Logger: Deleting Adding Item");
	query = patchAttributes(query);

	return orig_SecItemDelete(query);
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef  _Nullable *result);
static OSStatus override_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef  _Nullable *result){

	CFDictionaryRef uquery = patchAttributes(query);
    OSStatus status = orig_SecItemCopyMatching(query, result);;

    NSLog(@"GroupPatcher Logger: Begin Copying Items (%@) to (%@) with response (%i)", query, uquery, (int)status);

	return status;
}


// static inline void accessGroups(void){
//     SEL accessGroup = @selector(accesGroup);
//     MSHookMessageEx(
//         NSClassFromString(@"LSKeychainMultiItemController"),
//         accessGroup,
//         (IMP) &override_Keychain_accessGroups,
//         NULL
//         );
//     MSHookMessageEx(
//         NSClassFromString(@"LSKeychainItemController"),
//         accessGroup,
//         (IMP) &override_Keychain_accessGroups,
//         NULL
//         );
//     MSHookMessageEx(
//         NSClassFromString(@"FBKeychainItemController"),
//         accessGroup,
//         (IMP) &override_Keychain_accessGroups,
//         NULL
//         );
//     MSHookMessageEx(
//         NSClassFromString(@"FXAccountQuery"),
//         accessGroup,
//         (IMP) &override_Keychain_accessGroups,
//         NULL
//         );
//     MSHookMessageEx(
//         NSClassFromString(@"FXDeviceQuery"),
//         accessGroup,
//         (IMP) &override_Keychain_accessGroups,
//         NULL
//         );
// }

__attribute__((constructor)) static void Siuuuu(void){
    const struct mach_header *mach_header = _dyld_get_image_header(0);
    NSDictionary *entitlements = entitlementsForImage(mach_header, nil);
    keychainPrefix = entitlements[@"keychain-access-groups"][0];

    MSHookMessageEx(
        NSClassFromString(@"NSFileManager"),
        @selector(containerURLForSecurityApplicationGroupIdentifier:),
        (IMP) &override_NSFileManager_container,
        (IMP*) &orig_NSFileManager_container
        );
    
    MSHookMessageEx(
        NSClassFromString(@"NSUserDefaults"),
        @selector(initWithSuiteName:),
        (IMP) &override_NSUserDefaults_suit,
        (IMP*) &orig_NSUserDefaults_suit
        );

    MSHookMessageEx(
        objc_getMetaClass("NSHTTPCookieStorage"),
        @selector(sharedCookieStorageForGroupContainerIdentifier:),
        (IMP) &override_NSHTTPCookieStorage_container,
        (IMP*) &orig_NSHTTPCookieStorage_container
        );
    
    // Keychain hooks
    // accessGroups();
    NSLog(@"GroupPatcher Logger: Begin Fishhooking");
    rebind_symbols(
		(struct rebinding[4]){
			{"SecItemAdd",override_SecItemAdd,(void *)&orig_SecItemAdd},
            {"SecItemUpdate",override_SecItemUpdate,(void *)&orig_SecItemUpdate},
            {"SecItemDelete",override_SecItemDelete,(void *)&orig_SecItemDelete},
            {"SecItemCopyMatching",override_SecItemCopyMatching,(void *)&orig_SecItemCopyMatching}
			},
		4
	);
    NSLog(@"GroupPatcher Logger: Done Fishhooking");

}