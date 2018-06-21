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

+ (NSString *)iOSPublicKeyStringForServerByTag:(nonnull NSString *)aPublicKeyTag;
+ (NSString *)iOSPublicKeyStringForServer;


#pragma mark - External publicKey/privateKey


+ (NSString *)encryptString:(nonnull NSString *)aPlanString publicKey:(nonnull NSString *)aPublicKeyString tag:(nullable NSString *)aTag;
+ (NSString *)decryptString:(nonnull NSString *)aEncryptedString privateKey:(nonnull NSString *)aPrivateKeyString tag:(nullable NSString *)aTag;


#pragma mark - iOS publicKey Encrypt


+ (NSString *)iOSKeyEncryptString:(nonnull NSString *)aPlanString tag:(nonnull NSString *)aPublicKeyTag;
+ (NSString *)iOSKeyEncryptString:(nonnull NSString *)aPlanString;


#pragma mark - iOS privateKey Decrypt


+ (NSString *)iOSKeyDecryptString:(nonnull NSString *)aEncryptedString tag:(nonnull NSString *)aPrivateKeyTag;
+ (NSString *)iOSKeyDecryptString:(nonnull NSString *)aEncryptedString;

@end
