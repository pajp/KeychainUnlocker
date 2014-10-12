//
//  SetupViewController.m
//  KeychainUnlocker
//
//  Created by Rasmus Sten on 06-10-2014.
//  Copyright (c) 2014 Rasmus Sten. All rights reserved.
//

#import "SetupViewController.h"
#include <Security/Security.h>
#include <sys/types.h>
#include <sys/stat.h>

@interface SetupViewController ()

@end

@implementation SetupViewController

- (instancetype) initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    if (self) {
        self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
        self.keys = [NSMutableDictionary new];
        [self loadView];
    }
    return self;
}

- (void) open
{
    [self.window makeKeyAndOrderFront:nil];
    [SetupViewController populateKeychainList:self.keychainList onlyUnlockable:NO];
    [self populateKeyList:self.keyList andKeyMap:self.keys];
}

+ (void) populateKeychainList:(NSPopUpButton*) keychainList onlyUnlockable:(BOOL) unlockable
{
    [keychainList removeAllItems];
    NSFileManager* fm = [NSFileManager defaultManager];
    NSEnumerator* keychainEnumerator = [fm enumeratorAtPath:[@"~/Library/Keychains" stringByExpandingTildeInPath]];
    NSString* file;
    while (file = [keychainEnumerator nextObject]) {
        if (![[file pathExtension] isEqualToString:@"keychain"]) {
            continue;
        }
        NSString* keychainName = [[file lastPathComponent] stringByDeletingPathExtension];
        NSString* passwordFileName = [NSString stringWithFormat:[@"~/keychain-passwords/%@" stringByExpandingTildeInPath], keychainName];
        if (unlockable && ![fm fileExistsAtPath:passwordFileName]) {
            NSLog(@"No password file %@ for keychain %@, ignoring", passwordFileName, keychainName);
            continue;
        }
        [keychainList addItemWithTitle:keychainName];
        if ([keychainName isEqualToString:@"login"]) {
            [keychainList selectItemWithTitle:@"login"];
        }

    }
}

- (void) populateKeyList:(NSPopUpButton*)keyList andKeyMap:(NSMutableDictionary*) keys
{
    [keyList removeAllItems];
    NSTask* pkcs15tool = [NSTask new];
    pkcs15tool.launchPath = @"/usr/local/bin/pkcs15-tool";
    pkcs15tool.arguments = @[ @"--list-keys" ];
    NSPipe* stdout = [NSPipe new];
    pkcs15tool.standardOutput = stdout;
    
    [pkcs15tool launch];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [pkcs15tool waitUntilExit];
        if (pkcs15tool.terminationStatus) {
            NSLog(@"Error listing keys using pkcs15-tool (%d)", pkcs15tool.terminationStatus);
            return;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSData* outputBytes = [[stdout fileHandleForReading] readDataToEndOfFile];
            NSString* output = [[NSString alloc] initWithData:outputBytes encoding:NSUTF8StringEncoding];
            __block NSString* title = nil;
            [output enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
                if ([line isEqualToString:@""]) return;
                if ([line hasPrefix:@"\t"]) {
                    line = [line stringByReplacingOccurrencesOfString:@"\t" withString:@""];
                    //NSLog(@"Data line: %@", line);
                    if ([line hasPrefix:@"ID"]) {
                        NSArray* keyvalue = [line componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\t: "]];
                        [keyvalue enumerateObjectsUsingBlock:^(NSString* idString, NSUInteger idx, BOOL *stop) {
                            if ([idString isEqualToString:@""] || [idString isEqualToString:@"ID"]) {
                                return;
                            }
                            NSLog(@"Found key ID %@ for key %@", idString, title);
                            [keyList addItemWithTitle:[NSString stringWithFormat:@"%@ (ID: %@)", title, idString]];
                            NSMenuItem* item = [keyList lastItem];
                            item.representedObject = keys[idString] = @{ @"title" : title, @"id": idString };
                            NSLog(@"Saved key %@", item.representedObject);
                            if ([title rangeOfString:@"Encryption"].location != NSNotFound ||
                                [title rangeOfString:@"encryption"].location != NSNotFound) {
                                [keyList selectItem:item];
                            }
                        }];
                    }
                } else {
                    title = line;
                }
            }];
        });
    });
}

- (NSData*)readPublicKey:(NSString*) keyId {
    NSTask* pkcs15tool = [NSTask new];
    pkcs15tool.launchPath = @"/usr/local/bin/pkcs15-tool";
    pkcs15tool.arguments = @[ @"--read-public-key", keyId];
    NSPipe* stdout = [NSPipe new];
    pkcs15tool.standardOutput = stdout;
    [pkcs15tool launch];
    [pkcs15tool waitUntilExit];
    if (pkcs15tool.terminationStatus) {
        NSLog(@"Error reading public key for key %@: %d", keyId, pkcs15tool.terminationStatus);
        return nil;
    }
    return [[stdout fileHandleForReading] readDataToEndOfFile];
}

#define PUBKEY_FILE_TEMPLATE "/tmp/pubkey.XXXXXX"
- (NSData*)encrypt:(NSData*) plaintext withKey:(NSData*) publicKey {
    char* tempfilename = strdup(PUBKEY_FILE_TEMPLATE);
    NSData* tempfilenameData = [NSData dataWithBytesNoCopy:tempfilename length:strlen(tempfilename) freeWhenDone:YES];
    if (!tempfilenameData) {
        NSLog(@"Failed to create temporary file name wrapper object");
        return nil;
    }
    if (!mkstemp(tempfilename)) {
        NSLog(@"mkstemp() failed");
        return nil;
    }
    NSString* temporaryFile = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:tempfilename length:strlen(tempfilename)];
    if (![publicKey writeToFile:temporaryFile atomically:NO]) {
        NSLog(@"Failed to save public key to file %@", temporaryFile);
        return nil;
    }
    NSLog(@"Using public key in file %@", temporaryFile);
    NSData* encrypted = [self encrypt:plaintext withKeyFile:temporaryFile];
    unlink(tempfilename);
    return encrypted;
}

- (NSData*)encrypt:(NSData*) plaintext withKeyFile:(NSString*) filename {
    NSTask* openssl = [NSTask new];
    openssl.launchPath = @"/usr/bin/openssl";
    openssl.arguments = @[ @"rsautl", @"-encrypt", @"-pubin", @"-pkcs", @"-inkey", filename ];
    NSPipe* stdin = [NSPipe new];
    NSPipe* stdout = [NSPipe new];
    openssl.standardInput = stdin;
    openssl.standardOutput = stdout;
    [openssl launch];
    [stdin.fileHandleForWriting writeData:plaintext];
    [stdin.fileHandleForWriting closeFile];
    [openssl waitUntilExit];
    if (openssl.terminationStatus != 0) {
        NSLog(@"openssl rasutl failed with exit code %d", openssl.terminationStatus);
        return nil;
    }
    return [stdout.fileHandleForReading readDataToEndOfFile];
}

- (IBAction)generatePasswordAction:(id)sender {
    NSDictionary* key = (NSDictionary*)self.keyList.selectedItem.representedObject;
    NSLog(@"Selected key: %@", key);
    NSString* keychain = [self.keychainList titleOfSelectedItem];
    NSString* passwordFile = [[NSString stringWithFormat:@"~/keychain-passwords/%@", keychain] stringByExpandingTildeInPath];
    NSFileManager* fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:passwordFile]) {
        NSAlert* alert = [NSAlert alertWithMessageText:@"Password file already exists" defaultButton:@"OK" alternateButton:@"Reveal password file in Finder" otherButton:nil informativeTextWithFormat:@"A password file has already been created for keychain \"%@\". Delete it manually if you want to create new password for it.", keychain];
        [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
            if (returnCode == 0) {
                [[NSWorkspace sharedWorkspace] selectFile:passwordFile inFileViewerRootedAtPath:[passwordFile stringByDeletingLastPathComponent]];
            }
        }];
        return;
    }
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData* publicKey = [self readPublicKey:key[@"id"]];
        NSString* _password = [self generatePassword];
        NSData* password = [_password dataUsingEncoding:NSUTF8StringEncoding];
        NSData* encrypted = [self encrypt:password withKey:publicKey];
        if (![encrypted writeToFile:passwordFile atomically:YES]) {
            NSLog(@"Failed to write password file!");
            return;
        }
        
        char* scriptFileBytes = strdup("/tmp/setpasswordscript.XXXXXX");
        NSData* scriptFile = [NSData dataWithBytesNoCopy:scriptFileBytes length:strlen(scriptFileBytes) freeWhenDone:YES];
        int fd = mkstemp(scriptFileBytes);
        NSString* script = [NSString stringWithFormat:@"#!/bin/sh\n/usr/bin/security set-keychain-password ~/Library/Keychains/%@.keychain\n", keychain];
        NSData* d = [script dataUsingEncoding:NSUTF8StringEncoding];
        write(fd, d.bytes, d.length);
        close(fd);
        chmod(scriptFile.bytes, 0700);
        
        NSAlert* alert = [NSAlert alertWithMessageText:@"New password saved" defaultButton:@"Open Terminal and run the 'security set-keychain-password' command" alternateButton:@"That's OK, I'll do it later" otherButton:nil informativeTextWithFormat:@"A password was generated and stored for the %@ keychain. You need to manually change the keychain password, and can do so using the 'security set-keychain-password' command (or using Keychain Access, but then you can't paste the password into the password field).\n\n"
                          "The generated password is:\n%@\n\nIt has been copied to your clipboard and will remain there for five minutes.", keychain, _password];
        NSPasteboard* pb = [NSPasteboard pasteboardWithName:NSGeneralPboard];
        [pb clearContents];
        [pb writeObjects:@[ _password ]];
        dispatch_async(dispatch_get_main_queue(), ^{
            [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
                NSLog(@"final sheet return code: %ld", (long)returnCode);
                if (returnCode == 1) {
                    [[NSWorkspace sharedWorkspace] openFile:[fm stringWithFileSystemRepresentation:scriptFile.bytes length:scriptFile.length] withApplication:@"Terminal"];
                }
            }];
        });
        NSLog(@"ok");
    });
}

#define RANDBUFFERSIZE 32

- (NSData*) randomData
{
    void* buf = malloc(RANDBUFFERSIZE);
    arc4random_buf(buf, RANDBUFFERSIZE);
    return [NSData dataWithBytesNoCopy:buf length:RANDBUFFERSIZE freeWhenDone:YES];
}

- (NSString*) generatePassword
{
    return base64enc([self randomData]);;
}

static NSData *base64helper(NSData *input, SecTransformRef transform)
{
    NSData *output = nil;
    
    if (!transform)
        return nil;
    
    if (SecTransformSetAttribute(transform, kSecTransformInputAttributeName, CFBridgingRetain(input), NULL))
        output = (NSData *)CFBridgingRelease(SecTransformExecute(transform, NULL));
    
    CFRelease(transform);
    
    return output;
}

NSString *base64enc(NSData *input)
{
    SecTransformRef transform = SecEncodeTransformCreate(kSecBase64Encoding, NULL);
    
    return [[NSString alloc] initWithData:base64helper(input, transform) encoding:NSASCIIStringEncoding];
}
@end
