//
//  BreadWalletCommons.h
//  BreadWallet
//
//  Created by alon muroch on 4/1/15.
//  Copyright (c) 2015 Aaron Voisine. All rights reserved.
//

#ifndef BreadWallet_BreadWalletCommons_h
#define BreadWallet_BreadWalletCommons_h

//#define BITCOIN_TESTNET    1
#define SATOSHIS           100000000
#define MAX_MONEY          (21000000LL*SATOSHIS)
#define PARALAX_RATIO      0.25
//#define TX_FEE_0_8_RULES   1

#define BTC          @"\xC9\x83"     // capital B with stroke (utf-8)
#define BITS         @"\xC6\x80"     // lowercase b with stroke (utf-8)
#define NARROW_NBSP  @"\xE2\x80\xAF" // narrow no-break space (utf-8)
#define LDQUOTE      @"\xE2\x80\x9C" // left double quote (utf-8)
#define RDQUOTE      @"\xE2\x80\x9D" // right double quote (utf-8)
#define DISPLAY_NAME [NSString stringWithFormat:LDQUOTE @"%@" RDQUOTE,\
NSBundle.mainBundle.infoDictionary[@"CFBundleDisplayName"]]

#define HAVE_CONFIG_H 1 // for libsecp256k1
#define DETERMINISTIC 1

#if ! DEBUG
#define NSLog(...)
#endif

#endif
