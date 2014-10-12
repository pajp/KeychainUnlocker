//
//  SetupViewController.h
//  KeychainUnlocker
//
//  Created by Rasmus Sten on 06-10-2014.
//  Copyright (c) 2014 Rasmus Sten. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface SetupViewController : NSViewController
@property (weak) IBOutlet NSPopUpButton *keyList;
@property (weak) IBOutlet NSPopUpButton *keychainList;
@property (strong) IBOutlet NSWindow *window;
@property NSMutableDictionary* keys;
- (void) open;
+ (void) populateKeychainList:(NSPopUpButton*) keychainList onlyUnlockable:(BOOL) unlockable;
@end
