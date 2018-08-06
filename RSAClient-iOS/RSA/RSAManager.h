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


+ (OSStatus)generateKeyPairWithPublicKeyTag:(nonnull NSString *)aPublicKeyTag privateKeyTag:(nonnull NSString *)aPrivateKeyTag;
+ (OSStatus)generateKeyPair;

+ (void)removeAllRSAKeys;

+ (NSString *)publicKeyStringByTag:(nonnull NSString *)aPublicKeyTag;
+ (NSString *)iOSPublicKeyString;


#pragma mark - External publicKey/privateKey


+ (NSString *)encryptString:(nonnull NSString *)aPlanString publicKey:(nonnull NSString *)aPublicKeyString tag:(nullable NSString *)aPublicKeyTag;
+ (NSString *)decryptString:(nonnull NSString *)aEncryptedString privateKey:(nonnull NSString *)aPrivateKeyString tag:(nullable NSString *)aPrivateKeyTag;


#pragma mark - iOS publicKey Encrypt


+ (NSString *)encryptString:(nonnull NSString *)aPlanString tag:(nonnull NSString *)aPublicKeyTag;
+ (NSString *)iOSKeyEncryptString:(nonnull NSString *)aPlanString;


#pragma mark - iOS privateKey Decrypt


+ (NSString *)decryptString:(nonnull NSString *)aEncryptedString tag:(nonnull NSString *)aPrivateKeyTag;
+ (NSString *)iOSKeyDecryptString:(nonnull NSString *)aEncryptedString;

@end
