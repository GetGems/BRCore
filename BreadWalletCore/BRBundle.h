//
//  BRBundle.h
//  BreadWalletCore
//
//  Created by alon muroch on 7/30/15.
//  Copyright (c) 2015 alon muroch. All rights reserved.
//

#ifndef BreadWalletCore_BRBundle_h
#define BreadWalletCore_BRBundle_h

#import "BRWallet.h"

#define BRBundle [NSBundle bundleWithPath:[[[NSBundle bundleForClass:[BRWallet class]] resourcePath] stringByAppendingString:@"/BreadWalletCore.bundle"]]

#endif
