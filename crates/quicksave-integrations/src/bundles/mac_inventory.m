// SPDX-License-Identifier: GPL-3.0-only
// Public Apple APIs only. Candidate URLs are metadata hints, never root grants.
// No application launch, directory enumeration, credential or data-file access.
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <string.h>

@interface QuickSaveInventoryStatus : NSObject
@property(atomic) BOOL limited;
@property(atomic) BOOL finished;
@end
@implementation QuickSaveInventoryStatus
@end

static NSData *encodeInventory(NSArray<NSString *> *paths, BOOL complete,
                               BOOL limited, NSUInteger rejected) {
    // Box BOOLs explicitly: boxing a C logical expression boxes an int, which
    // NSJSONSerialization emits as 0/1 instead of the Rust protocol's boolean.
    return [NSJSONSerialization dataWithJSONObject:@{
        @"paths": paths, @"indexComplete": @(complete),
        @"limited": @(limited), @"rejected": @(rejected)
    } options:0 error:nil];
}

// Pure linked protocol fixture: exercises the production encoder without
// accessing NSWorkspace, Spotlight, any filesystem, or any user application.
int quicksave_mac_inventory_protocol_fixture(unsigned char *output,
                                             size_t capacity, size_t *written) {
    if (!output || !written) return 1;
    @autoreleasepool {
        NSData *data = encodeInventory(@[], YES, NO, 0);
        if (!data || data.length > capacity) return 2;
        memcpy(output, data.bytes, data.length);
        *written = data.length;
        return 0;
    }
}

int quicksave_mac_inventory(const char *const *scope_paths, size_t scope_count,
                           size_t maximum, unsigned char *output,
                           size_t capacity, size_t *written) {
    if (!scope_paths || !output || !written || scope_count == 0 ||
        scope_count > 128 || maximum == 0 || maximum > 4096 ||
        capacity > 4 * 1024 * 1024) return 1;
    *written = 0;
    __block int failureStage = 4;
    @autoreleasepool {
        @try {
            NSMutableArray<NSURL *> *scopes = [NSMutableArray array];
            for (size_t i = 0; i < scope_count; i++) {
                if (!scope_paths[i] || strnlen(scope_paths[i], 4097) > 4096) return 1;
                NSString *path = [NSString stringWithUTF8String:scope_paths[i]];
                if (!path || !path.isAbsolutePath) return 1;
                [scopes addObject:[NSURL fileURLWithPath:path isDirectory:YES]];
            }
            NSMutableSet<NSString *> *paths = [NSMutableSet set];
            QuickSaveInventoryStatus *status = [[QuickSaveInventoryStatus alloc] init];
            __block NSUInteger rejected = 0;
            __block NSUInteger pathBytes = 0;
            void (^addURL)(NSURL *) = ^(NSURL *url) {
                if (!url || !url.isFileURL) return;
                NSString *path = url.path;
                NSUInteger bytes = [path lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
                if (!path || !path.isAbsolutePath || bytes == 0 || bytes > 4096 ||
                    [path rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound ||
                    [path containsString:@"\\"] ||
                    [path.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
                    rejected++; return;
                }
                // Restricts metadata hints, NOT a native containment proof.
                BOOL inScope = NO;
                for (NSURL *scope in scopes) {
                    NSString *prefix = [scope.path stringByAppendingString:@"/"];
                    if ([path hasPrefix:prefix]) { inScope = YES; break; }
                }
                if (!inScope || [paths containsObject:path]) return;
                if (paths.count >= maximum || bytes > 2 * 1024 * 1024 - pathBytes) {
                    status.limited = YES; return;
                }
                [paths addObject:path]; pathBytes += bytes;
            };
            failureStage = 10;
            NSWorkspace *workspace = NSWorkspace.sharedWorkspace;
            void (^addApplication)(NSURL *, NSString *) = ^(NSURL *url, NSString *identifier) {
                // Do not query metadata for protected products' application data.
                if ([identifier isEqualToString:@"com.noland.connect"] ||
                    [identifier isEqualToString:@"app.quicksave.desktop"]) return;
                addURL(url);
                if (identifier.length > 0 && identifier.length <= 512) {
                    // Public NSWorkspace lookup backed by Launch Services.
                    // Retain the original URL too: duplicate installations must
                    // remain ambiguous, not silently replaced by the preferred one.
                    failureStage = 12;
                    addURL([workspace URLForApplicationWithBundleIdentifier:identifier]);
                }
            };
            failureStage = 11;
            NSArray<NSRunningApplication *> *running = workspace.runningApplications;
            if (running.count > 8192) {
                status.limited = YES;
            } else {
                for (NSRunningApplication *application in running) {
                    addApplication(application.bundleURL, application.bundleIdentifier);
                }
            }

            failureStage = 20;
            NSMetadataQuery *query = [[NSMetadataQuery alloc] init];
            query.searchScopes = scopes;
            query.predicate = [NSPredicate predicateWithFormat:
                @"kMDItemContentTypeTree == %@", @"com.apple.application-bundle"];
            NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
            id done = [center addObserverForName:NSMetadataQueryDidFinishGatheringNotification
                object:query queue:nil usingBlock:^(NSNotification *notification) {
                    (void)notification;
                    status.finished = YES;
                }];
            id progress = [center addObserverForName:NSMetadataQueryGatheringProgressNotification
                object:query queue:nil usingBlock:^(NSNotification *notification) {
                    (void)notification;
                    if (query.resultCount > maximum) status.limited = YES;
                }];
            BOOL started = NO;
            @try {
                failureStage = 21;
                started = [query startQuery];
                NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5.0];
                // Event-driven, finite initial gathering; no continuous query,
                // filesystem polling, synchronous unbounded wait, or shell tool.
                while (started && !status.finished && !status.limited && deadline.timeIntervalSinceNow > 0) {
                    if (![NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode
                                               beforeDate:deadline]) break;
                }
                failureStage = 22;
                [query disableUpdates];
                NSUInteger count = query.resultCount;
                if (count > maximum) status.limited = YES;
                for (NSUInteger i = 0; i < MIN(count, maximum); i++) {
                    NSMetadataItem *item = [query resultAtIndex:i];
                    id path = [item valueForAttribute:NSMetadataItemPathKey];
                    id identifier = [item valueForAttribute:@"kMDItemCFBundleIdentifier"];
                    if (![path isKindOfClass:NSString.class]) { rejected++; continue; }
                    if (![identifier isKindOfClass:NSString.class]) identifier = nil;
                    addApplication([NSURL fileURLWithPath:path], identifier);
                }
            } @finally {
                [query stopQuery];
                [center removeObserver:done];
                [center removeObserver:progress];
            }
            failureStage = 30;
            NSData *data = encodeInventory(
                [[paths allObjects] sortedArrayUsingSelector:@selector(compare:)],
                (BOOL)(started && status.finished), status.limited, rejected);
            if (!data || data.length > capacity) return 2;
            memcpy(output, data.bytes, data.length);
            *written = data.length;
            return 0;
        } @catch (NSException *exception) {
            // Never forward OS error bodies, paths or exception descriptions.
            return failureStage;
        }
    }
}
