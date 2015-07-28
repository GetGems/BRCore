//
//  MagicalRecord+BreadWallet.m
//  BreadWalletCore
//
//  Created by alon muroch on 7/27/15.
//  Copyright (c) 2015 alon muroch. All rights reserved.
//

#import "MagicalRecord+BreadWallet.h"

@implementation MagicalRecord (BreadWallet)

+ (void)BR_initializeFromBundle:(NSBundle*)bundle
{
    // Core data
    NSManagedObjectModel *model = [NSManagedObjectModel MR_newModelNamed:@"BreadWallet.momd" inBundle:bundle];
    [NSManagedObjectModel  MR_setDefaultManagedObjectModel:model];
    [MagicalRecord setupCoreDataStackWithAutoMigratingSqliteStoreNamed:@"BreadWallet.sqlite"];
}

@end
