//
//  AppDelegate.h
//  KeychainUnlocker
//
//  Created by Rasmus Sten on 04-10-2014.
//  Copyright (c) 2014 Rasmus Sten. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (weak) IBOutlet NSImageView *icon;
@property (weak) IBOutlet NSSecureTextField *passwordField;
@property (weak) IBOutlet NSProgressIndicator *spinner;

@end

