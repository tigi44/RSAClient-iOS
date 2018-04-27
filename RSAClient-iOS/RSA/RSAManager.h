//
//  RSAManager.h
//  RSAClient-iOS
//
//  Created by tigi on 2018. 4. 27..
//  Copyright © 2018년 tigi. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAManager : NSObject

#pragma mark -

+ (OSStatus)generateKeyPairWithPublicKey;
+ (void)removeAllRSAKeys;

+ (NSString *)iOSPublicKeyStringForServer;

#pragma mark -

+ (NSString *)encryptString:(nonnull NSString *)aPlanString publicKey:(nonnull NSString *)aPublicKeyString tag:(NSString *)aTag;
+ (NSString *)serverKeyEncryptString:(nonnull NSString *)aPlanString;
+ (NSString *)iOSKeyEncryptString:(nonnull NSString *)aPlanString;

+ (NSString *)decryptString:(nonnull NSString *)aEncryptedString privateKey:(nonnull NSString *)aPrivateKeyString tag:(NSString *)aTag;
+ (NSString *)serverKeyDecryptString:(nonnull NSString *)aEncryptedString;
+ (NSString *)iOSKeyDecryptString:(nonnull NSString *)aEncryptedString;

#pragma mark -
+ (NSData *)RSAEncryptData:(NSData *)aData Key:(SecKeyRef)aKey;
+ (NSData *)RSADecryptData:(NSData *)aData Key:(SecKeyRef)aKey;

@end
