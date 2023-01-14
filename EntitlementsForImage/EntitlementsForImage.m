#import "EntitlementsForImage.h"
#import <mach-o/loader.h>

#if __has_include(<Kernel/kern/cs_blobs.h>)
#   import <Kernel/kern/cs_blobs.h>
#else
    /* some Darwin distributions don't provide the cs_blobs header
     * copy it from the macOS SDK if available, otherwise one of
     * https://opensource.apple.com/source/xnu/xnu-4903.221.2/osfmk/kern/cs_blobs.h.auto.html
     * https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/osfmk/kern/cs_blobs.h
     *   (these should be API and ABI stable, so any version of xnu should be fine)
     */
#   import "cs_blobs.h"
#endif


/**
 * @function entitlementsForImage
 * @param mh A pointer to the mach_header of the image to search. The entire image must be loaded into readable memory. The header may be either @c mach_header or @c mach_header_64
 * @param error An error to be filled out in the event of one of the following:
 *     (1) The type of mach_header provided can not be identified
 *     (2) The signature blob of the image could not be found
 *     (3) The signature blob has an invalid magic
 *     (4) The entitlement blob could not be found
 *     (*) The entitlemnt blob was not able to be converted to a dictionary
 * @return The embedded entitlements of a given image
 * @discussion Based on @c Security/codesign_wrapper/check_entitlements.c . This routine does not check the validity of the code signature
 */
NSDictionary *_Nullable entitlementsForImage(const struct mach_header *_Nonnull const mh, NSError *_Nullable *_Nullable error) {
    const struct load_command *lc = NULL;
    if (mh->magic == MH_MAGIC_64) {
        lc = (void *)mh + sizeof(struct mach_header_64);
    } else if (mh->magic == MH_MAGIC) {
        lc = (void *)mh + sizeof(struct mach_header);
    } else {
        if (error) {
            *error = [NSError errorWithDomain:@"null.leptos.entitlementsForImage" code:1 userInfo:@{
                NSLocalizedDescriptionKey : @"mach_header has an unknown magic"
            }];
        }
        return nil;
    }
    
    const CS_SuperBlob *superBlob = NULL;
    for (uint32_t cmd = 0; cmd < mh->ncmds; cmd++) {
        if (lc->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command *sb = (void *)lc;
            superBlob = (void *)mh + sb->dataoff;
            break;
        }
        lc = (void *)lc + lc->cmdsize;
    }
    if (!superBlob) {
        if (error) {
            *error = [NSError errorWithDomain:@"null.leptos.entitlementsForImage" code:2 userInfo:@{
                NSLocalizedDescriptionKey : @"Could not find signature blob"
            }];
        }
        return nil;
    }
    
    if (ntohl(superBlob->magic) != CSMAGIC_EMBEDDED_SIGNATURE) {
        if (error) {
            *error = [NSError errorWithDomain:@"null.leptos.entitlementsForImage" code:3 userInfo:@{
                NSLocalizedDescriptionKey : @"Signature blob has an unknown magic"
            }];
        }
        return nil;
    }
    NSData *blobData = NULL;
    const uint32_t blobCount = ntohl(superBlob->count);
    for (uint32_t i = 0; i < blobCount; i++) {
        const CS_GenericBlob *blob = (void *)superBlob + ntohl(superBlob->index[i].offset);
        if (ntohl(blob->magic) != CSMAGIC_EMBEDDED_ENTITLEMENTS) {
            continue;
        }

        blobData = [NSData dataWithBytesNoCopy:(void *)blob->data length:ntohl(blob->length) - offsetof(CS_GenericBlob, data) freeWhenDone:NO];
        break;
    }
    if (!blobData) {
        if (error) {
            *error = [NSError errorWithDomain:@"null.leptos.entitlementsForImage" code:4 userInfo:@{
                NSLocalizedDescriptionKey : @"Could not find entitlements blob"
            }];
        }
        return nil;
    }
    
    return [NSPropertyListSerialization propertyListWithData:blobData options:NSPropertyListImmutable format:NULL error:error];
}
