#import <Foundation/Foundation.h>
#import <substrate.h>


static NSDictionary * replacement;

static NSString * replaceKey(NSString *origKey) {
    NSLog(@"[GroupPatcher] orig key: %@", origKey);
    NSString *newKey = replacement[origKey];
    if (newKey != nil) {
        NSLog(@"[GroupPatcher] Replacing key: %@ to : %@", origKey, newKey);
        return newKey;
    }
    return origKey;
}

// -[NSFileManager containerURLForSecurityApplicationGroupIdentifier:]
static NSURL *(*orig_NSFileManager_container)(id, SEL, id);
static NSURL *override_NSFileManager_container(id self, SEL _cmd, NSString *groupIdentifier){
    return orig_NSFileManager_container(self, _cmd, replaceKey(groupIdentifier));
}

// -[NSUserDefaaults initWithSuiteName:]
static NSUserDefaults *(*orig_NSUserDefaults_suit)(id, SEL, id);
static NSUserDefaults *override_NSUserDefaults_suit(id self, SEL _cmd, NSString *suit){
    return orig_NSUserDefaults_suit(self, _cmd, replaceKey(suit));
}

// +[NSHTTPCookieStorage sharedCookieStorageForGroupContainerIdentifier:]
static NSHTTPCookieStorage *(*orig_NSHTTPCookieStorage_container)(id, SEL, id);
static NSHTTPCookieStorage *override_NSHTTPCookieStorage_container(NSHTTPCookieStorage *self, SEL _cmd, NSString *identifier){
    return orig_NSHTTPCookieStorage_container(self, _cmd, replaceKey(identifier));
}

__attribute__((constructor)) static void Siuuuu(void){

    // "group.com.facebook.family" gets replaced to "group.dev.extbh.family"
    replacement = @{
        @"group.com.facebook.family": @"group.dev.extbh.family",
        @"group.com.facebook.Messenger": @"group.dev.extbh.Messenger",
        @"group.com.facebook.msysstorage": @"group.dev.extbh.msysstorage",
        @"T84QZS65DQ.platformFamily" : @"82DA3FVS98.platformFamily"
    };

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
}
