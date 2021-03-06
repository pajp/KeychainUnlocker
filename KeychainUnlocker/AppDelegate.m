//
//  AppDelegate.m
//  KeychainUnlocker
//
// This application will attempt unlock keychains using a password
// stored in encrypted form in ~/keychain-passwords/<keychainname>.
// The password is encrypted and decrypted using an RSA key on a
// smart card.
//
//
//  Created by Rasmus Sten on 04-10-2014.
//  Copyright (c) 2014 Rasmus Sten. All rights reserved.
//

#import "AppDelegate.h"
#include <Security/Security.h>
#include <QuartzCore/QuartzCore.h>

@interface AppDelegate () {
    BOOL justLaunched;
}

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate


- (void)applicationWillFinishLaunching:(NSNotification *)notification {
    [[NSUserDefaults standardUserDefaults] registerDefaults:@{ @"key-id" : @( 2 )
                                                               }];
    self.keys = [NSMutableDictionary new];
    justLaunched = YES;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    self.icon.image = [NSImage imageNamed:NSImageNameLockLockedTemplate];
    SecKeychainRef keychain = NULL;
    [SetupViewController populateKeychainList:self.keychainPicker onlyUnlockable:YES];
    if (self.keychainPicker.itemArray.count == 0) {
        [self openSetupView];
    }
    [self setupKeychain:&keychain];
}
- (IBAction)preferencesAction:(id)sender {
    [self openSetupView];
}

- (void) openSetupView
{
    if (!self.setupViewController) {
        self.setupViewController = [[SetupViewController alloc] initWithNibName:@"SetupViewController" bundle:nil];
    }
    [self.setupViewController open];
}

- (NSString*)setupKeychain:(SecKeychainRef*) keychain
{
    NSString* keychainName = self.keychainPicker.selectedItem.title;
    NSString* keychainFile = [NSString stringWithFormat:@"%@/Library/Keychains/%@.keychain",
                              NSHomeDirectory(),
                              keychainName];
    OSStatus openStatus = SecKeychainOpen(keychainFile.fileSystemRepresentation, keychain);
    if (openStatus != errSecSuccess) {
        NSLog(@"Failed to open keychain %@: %d", keychainFile, openStatus);
        return nil;
    }
    SecKeychainStatus keychainStatus;
    OSStatus statusStatus = SecKeychainGetStatus(*keychain, &keychainStatus);
    if (statusStatus != errSecSuccess) {
        NSString* errorString = CFBridgingRelease(SecCopyErrorMessageString(statusStatus, NULL));
        NSLog(@"Error getting keychain status: %@ (%d) (keychain: %@)",  errorString, statusStatus, keychainFile);
        return nil;
    }
    NSLog(@"Keychain status: %d", keychainStatus);
    if ((keychainStatus & kSecUnlockStateStatus) == kSecUnlockStateStatus) {
        NSLog(@"Keychain already unlocked");
        [self yippie:YES];
        return nil;
    } else {
        [self yippie:NO];
    }
    return keychainFile;
}

- (IBAction)passwordFieldAction:(id)sender {
    SecKeychainRef keychain = NULL;
    NSString* keychainFile = [self setupKeychain:&keychain];
    if (!keychainFile) {
        return;
    }

    if ([self.passwordField.stringValue isEqualToString:@""]) {
        NSLog(@"Waiting for PIN entry");
        return;
    }

    [self.spinner setHidden:NO];
    [self.spinner startAnimation:nil];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        
        NSTask* task = [NSTask new];
        task.launchPath = @"/usr/local/bin/pkcs15-crypt";
        NSString* keychainName = [[keychainFile lastPathComponent] stringByDeletingPathExtension];
        NSString* passwordFile = [NSString stringWithFormat:@"%@/keychain-passwords/%@", NSHomeDirectory(), keychainName];
        NSInteger keyId = [[NSUserDefaults standardUserDefaults] integerForKey:@"key-id"];
        NSLog(@"Decrypting using key %ld", (long)keyId);
        
        task.arguments = @[ /*@"-vvv",*/ @"-R", @"--decipher", @"-k", @(keyId).stringValue, @"-i", passwordFile, @"-p", @"-" ];

        NSPipe* stdout = [NSPipe new];
        NSPipe* stdin = [NSPipe new];
        NSPipe* stderr = [NSPipe new];
        task.standardOutput = stdout;
        task.standardInput = stdin;
        task.standardError = stderr;
        NSString* toSend = [NSString stringWithFormat:@"%@\n", self.passwordField.stringValue];
        NSData* pin = [toSend dataUsingEncoding:NSUTF8StringEncoding];
        [task launch];
        NSFileHandle* stdinHandle = stdin.fileHandleForWriting;
        
        [stdinHandle writeData:pin];
        [task waitUntilExit];

        if (task.terminationStatus != 0) {
            NSString* pkcs15cryptError = [[NSString alloc] initWithData:[[stderr fileHandleForReading] readDataToEndOfFile] encoding:NSUTF8StringEncoding];
            NSLog(@"Error: %@", pkcs15cryptError);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.spinner stopAnimation:nil];
                [self.spinner setHidden:YES];
                NSAlert* alert = [NSAlert alertWithMessageText:@"Failed to decrypt password" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"There was an error decrypting the keychain password.\n%@", pkcs15cryptError];
                [alert beginSheetModalForWindow:self.window completionHandler:nil];
            });
            return;
        }
        
        NSData* password = [[stdout fileHandleForReading] readDataToEndOfFile];
        
        size_t passwordLength = password.length;
        
        OSStatus unlockStatus = SecKeychainUnlock(keychain, (UInt32)passwordLength, [password bytes], TRUE);
        if (unlockStatus != errSecSuccess) {
            NSLog(@"Failed to unlock keychain: %d", unlockStatus);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.spinner stopAnimation:nil];
                [self.spinner setHidden:YES];
                NSString* errorMsg = CFBridgingRelease(SecCopyErrorMessageString(unlockStatus, NULL));
                NSAlert* alert = [NSAlert alertWithMessageText:@"Failed to unlock keychain" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"There was an error unlocking the keychain. %@", errorMsg];
                [alert beginSheetModalForWindow:self.window completionHandler:nil];
            });
            return;
        }
        NSLog(@"Successfully unlocked %@ keychain!", keychainName);
        [self yippie:YES];
    });
}


-(void) yippie:(BOOL)yay {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.icon.image = yay ? [NSImage imageNamed:NSImageNameLockUnlockedTemplate] : [NSImage imageNamed:NSImageNameLockLockedTemplate];
        [self.spinner stopAnimation:nil];
        [self.spinner setHidden:YES];
        
        CABasicAnimation* a = [CABasicAnimation new];
        a.keyPath = @"backgroundColor";
        a.fromValue = (__bridge id) ([(yay ? [NSColor whiteColor] : [NSColor greenColor]) CGColor]);
        a.toValue = (__bridge id)([(yay ? [NSColor greenColor] : [NSColor whiteColor]) CGColor]);
        [self.passwordField.layer addAnimation:a forKey:nil];
        self.passwordField.layer.backgroundColor = yay ? [[NSColor greenColor] CGColor] : [[NSColor whiteColor] CGColor];
        
        [self.passwordField setEnabled:!yay];
        
        if (justLaunched) {
            justLaunched = NO;
            return;
        }
        
        if (yay && self.exitOnSuccessCheckbox.integerValue) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                NSDictionary *f = @{NSViewAnimationTargetKey : self.window,
                                    NSViewAnimationEffectKey : NSViewAnimationFadeOutEffect};
                NSViewAnimation *va = [[NSViewAnimation alloc] initWithViewAnimations:@[f]];
                va.duration = 1.0;
                va.animationBlockingMode = NSAnimationNonblocking;
                [va startAnimation];
            });

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),dispatch_get_main_queue(), ^{
                [NSApp terminate:nil];
            });
        }
    });
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
}
- (IBAction)keychainPickerAction:(id)sender {
    SecKeychainRef keychain = NULL;
    [self setupKeychain:&keychain];
}

@end
