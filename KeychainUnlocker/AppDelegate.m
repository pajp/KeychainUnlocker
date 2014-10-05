//
//  AppDelegate.m
//  KeychainUnlocker
//
// This application will attempt unlock the login keychain using a password
// stored in encrypted form in ~/keychain-passwords/login.
//
// It is hard coded to use key with ID "2" on a smartcard to decrypt the password file.
// To change key ID:
//   defaults write nu.dll.KeychainUnlocker key-id
//
// The password file can encrypted like this:
// pkcs15-tool --read-public-key 2 > smartcard-crypt-pubkey # 2 = key ID
// echo -n 'PASSWORD' | openssl rsautl -encrypt -pubin -inkey smartcard-crypt-pubkey -pkcs -out ~/keychain-passwords/login
//
// Warning: the above line may store your password in your shell history.
// You may want to run "history -c" afterwards, and clear any Terminal scrollback
// buffers
//
//  Created by Rasmus Sten on 04-10-2014.
//  Copyright (c) 2014 Rasmus Sten. All rights reserved.
//

#import "AppDelegate.h"
#include <Security/Security.h>

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate



- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    self.icon.image = [NSImage imageNamed:NSImageNameLockLockedTemplate];
    [[NSUserDefaults standardUserDefaults] registerDefaults:@{ @"key-id" : @( 2 ) }];
}

- (IBAction)passwordFieldAction:(id)sender {
    SecKeychainRef keychain = NULL;
    NSString* keychainFile = [NSString stringWithFormat:@"%@/Library/Keychains/login.keychain", NSHomeDirectory()];
    OSStatus openStatus = SecKeychainOpen(keychainFile.fileSystemRepresentation, &keychain);
    if (openStatus != errSecSuccess) {
        NSLog(@"Failed to open keychain %@: %d", keychainFile, openStatus);
        return;
    }
    SecKeychainStatus keychainStatus;
    OSStatus statusStatus = SecKeychainGetStatus(keychain, &keychainStatus);
    if (statusStatus != errSecSuccess) {
        NSLog(@"Error getting keychain status: %d", statusStatus);
        return;
    }
    NSLog(@"Keychain status: %d", keychainStatus);
    if ((keychainStatus & kSecUnlockStateStatus) == kSecUnlockStateStatus) {
        NSLog(@"Keychain already unlocked, exiting");
        [NSApp terminate:nil];
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
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.spinner stopAnimation:nil];
            [self.spinner setHidden:YES];
        });
        self.icon.image = [NSImage imageNamed:NSImageNameLockUnlockedTemplate];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [NSApp terminate:nil];
        });
    });
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
}

@end
