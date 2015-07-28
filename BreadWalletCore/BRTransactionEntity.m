//
//  BRTransactionEntity.m
//  BreadWallet
//
//  Created by Aaron Voisine on 8/22/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import "BRTransactionEntity.h"
#import "BRTxInputEntity.h"
#import "BRTxOutputEntity.h"
#import "BRAddressEntity.h"
#import "BRTransaction.h"
#import "BRMerkleBlock.h"
#import <MagicalRecord.h>
#import "NSMutableData+Bitcoin.h"
#import <CommonCrypto/CommonDigest.h>

@implementation BRTransactionEntity

@dynamic txHash;
@dynamic blockHeight;
@dynamic timestamp;
@dynamic inputs;
@dynamic outputs;
@dynamic lockTime;

- (instancetype)setAttributesFromTx:(BRTransaction *)tx
{
    [MagicalRecord saveWithBlockAndWait:^(NSManagedObjectContext *localContext) {
        NSMutableOrderedSet *inputs = [[NSMutableOrderedSet alloc] initWithOrderedSet:self.inputs];//[self mutableOrderedSetValueForKey:@"inputs"];
        NSMutableOrderedSet *outputs = [[NSMutableOrderedSet alloc] initWithOrderedSet:self.outputs];//[self mutableOrderedSetValueForKey:@"outputs"];
        NSUInteger idx = 0;
        
        self.txHash = tx.txHash;
        self.blockHeight = tx.blockHeight;
        self.timestamp = tx.timestamp;
        
        while (inputs.count < tx.inputHashes.count) {
            [inputs addObject:[BRTxInputEntity MR_createEntityInContext:localContext]];
        }
        
        while (inputs.count > tx.inputHashes.count) {
            [inputs removeObjectAtIndex:inputs.count - 1];
        }
        
        for (BRTxInputEntity *e in inputs) {
            [e setAttributesFromTx:tx inputIndex:idx++];
        }
        
        while (outputs.count < tx.outputAddresses.count) {
            [outputs addObject:[BRTxOutputEntity MR_createEntityInContext:localContext]];
        }
        
        while (outputs.count > tx.outputAddresses.count) {
            [self removeObjectFromOutputsAtIndex:outputs.count - 1];
        }
        
        idx = 0;
        
        for (BRTxOutputEntity *e in outputs) {
            [e setAttributesFromTx:tx outputIndex:idx++];
        }
        
        self.lockTime = tx.lockTime;
    }];
    
    return self;
}

- (BRTransaction *)transaction
{
    BRTransaction *tx = [BRTransaction new];
    
    tx.txHash = self.txHash;
    tx.lockTime = self.lockTime;
    tx.blockHeight = self.blockHeight;
    tx.timestamp = self.timestamp;
    
    for (BRTxInputEntity *e in self.inputs) {
        [tx addInputHash:e.txHash index:e.n script:nil signature:e.signature sequence:e.sequence];
    }
    
    for (BRTxOutputEntity *e in self.outputs) {
        [tx addOutputScript:e.script amount:e.value];
    }
    
    return tx;
}

- (void)deleteObject
{
    for (BRTxInputEntity *e in self.inputs) { // mark inputs as unspent
        NSPredicate *predicate = [NSPredicate predicateWithFormat:@"txHash == %@ && n == %d", e.txHash, e.n];
        [[BRTxOutputEntity MR_findAllWithPredicate:predicate].lastObject setSpeed:NO];        
    }

    [self MR_deleteEntity];
}

@end
