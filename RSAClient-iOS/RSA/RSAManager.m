//
//  RSAManager.m
//  RSAClient-iOS
//
//  Created by tigi on 2018. 4. 27..
//  Copyright © 2018년 tigi. All rights reserved.
//

#import "RSAManager.h"

static NSString *const kExternalPublicKeyTag     = @"RSA_EXTERNAL_PUBLICKEY";
static NSString *const kExternalPrivateKeyTag    = @"RSA_EXTERNAL_PRIVATEKEY";

static NSString *const kRSALabel                 = @"RSALabel";

static NSString *const kiOSPublicKeyTag          = @"RSA_IOS_PUBLICKEY";
static NSString *const kiOSPrivateKeyTag         = @"RSA_IOS_PRIVATEKEY";

static NSString *const kTransformSecKeyRefToData = @"RSA_SECKEYREF_TO_DATA";

static int       const kRSAKeySize               = 2048;


@implementation RSAManager


#pragma mark - encrypt


+ (NSString *)iOSKeyEncryptString:(NSString * _Nonnull)aPlanString
{
    return [[self class] encryptString:aPlanString tag:kiOSPublicKeyTag];
}

+ (NSString *)encryptString:(NSString * _Nonnull)aPlanString tag:(NSString * _Nonnull)aPublicKeyTag
{
    SecKeyRef sPublicKeyRef  = NULL;
    NSString *sEncryptResult = nil;
    
    [[self class] secKeyRef:&sPublicKeyRef tag:aPublicKeyTag];
    if (sPublicKeyRef)
    {
        sEncryptResult = [[self class] encryptString:aPlanString secKeyRef:sPublicKeyRef];
    }
    
    return sEncryptResult;
}

+ (NSString *)encryptString:(NSString * _Nonnull)aPlanString publicKey:(NSString * _Nonnull)aPublicKeyString
{
    SecKeyRef sPublicKeyRef  = NULL;
    NSString *sEncryptResult = nil;
    
    sPublicKeyRef = [[self class] secExternalPublicKeyFromString:aPublicKeyString];
    if (sPublicKeyRef)
    {
        sEncryptResult = [[self class] encryptString:aPlanString secKeyRef:sPublicKeyRef];
    }
    
    return sEncryptResult;
}

+ (NSString *)encryptString:(NSString * _Nonnull)aPlanString secKeyRef:(SecKeyRef _Nonnull)aPublicKeyRef
{
    NSData   *sPlainData;
    NSData   *sCipherData;
    NSString *sEncryptResult = nil;
    
    sPlainData     = [aPlanString dataUsingEncoding:NSUTF8StringEncoding];
    sCipherData    = [[self class] RSAEncryptData:sPlainData Key:aPublicKeyRef];
    sEncryptResult = [[self class] base64EncodeWithData:sCipherData];
    
    return sEncryptResult;
}


#pragma mark - decrypt


+ (NSString *)iOSKeyDecryptString:(NSString * _Nonnull)aEncryptedString
{
    return [[self class] decryptString:aEncryptedString tag:kiOSPrivateKeyTag];
}

+ (NSString *)decryptString:(nonnull NSString *)aEncryptedString tag:(nonnull NSString *)aPrivateKeyTag
{
    SecKeyRef sPrivateKeyRef = NULL;
    NSString *sDecryptResult = nil;
    
    [[self class] secKeyRef:&sPrivateKeyRef tag:aPrivateKeyTag];
    if (sPrivateKeyRef)
    {
        sDecryptResult = [[self class] decryptString:aEncryptedString secKeyRef:sPrivateKeyRef];
    }
    
    return sDecryptResult;
}

+ (NSString *)decryptString:(NSString * _Nonnull)aEncryptedString privateKey:(NSString * _Nonnull)aPrivateKeyString
{
    SecKeyRef sPrivateKeyRef = NULL;
    NSString *sDecryptResult = nil;

    sPrivateKeyRef = [[self class] secExternalPrivateKeyFromString:aPrivateKeyString];
    if (sPrivateKeyRef)
    {
        sDecryptResult = [[self class] decryptString:aEncryptedString secKeyRef:sPrivateKeyRef];
    }
    
    return sDecryptResult;
}

+ (NSString *)decryptString:(NSString * _Nonnull)aEncryptedString secKeyRef:(SecKeyRef _Nonnull)aPrivateKeyRef
{
    NSData   *sCipherData;
    NSData   *sPlainData;
    NSString *sDecryptResult = nil;
    
    sCipherData    = [[self class] base64DecodeToData:aEncryptedString];
    sPlainData     = [[self class] RSADecryptData:sCipherData Key:aPrivateKeyRef];
    sDecryptResult = [[NSString alloc] initWithData:sPlainData encoding:NSUTF8StringEncoding];
    
    return sDecryptResult;
}


#pragma mark - get secKeyRef by a External public key string


+ (SecKeyRef)secExternalPublicKeyFromString:(NSString * _Nonnull)aExternalPublicKey
{
    SecKeyRef sSecKeyRef = NULL;
    
    if (@available(iOS 10.0, *))
    {
        sSecKeyRef = [[self class] SecKeyCreateWithPublicKey:aExternalPublicKey];
    }
    else
    {
        OSStatus  status = noErr;
        NSString *sTag   = kExternalPublicKeyTag;
        
        status = [[self class] SecItemAddPublicKey:aExternalPublicKey tag:sTag];
        if ((status != errSecSuccess) && (status != errSecDuplicateItem)) {
            sSecKeyRef = NULL;
        }
        
        status = [[self class] secKeyRef:&sSecKeyRef tag:sTag];
        if(status != errSecSuccess){
            sSecKeyRef = NULL;
        }
        
        status = [[self class] SecItemDeleteByTag:sTag];
    }
    
    return sSecKeyRef;
}

+ (OSStatus)SecItemDeleteByTag:(NSString * _Nonnull)aTag
{
    NSMutableDictionary *sKeyDic = [[NSMutableDictionary alloc] init];
    NSData              *sTag    = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    
    [sKeyDic setObject:(__bridge id)kSecClassKey             forKey:(__bridge id)kSecClass];
    [sKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA       forKey:(__bridge id)kSecAttrKeyType];
    [sKeyDic setObject:sTag                                  forKey:(__bridge id)kSecAttrApplicationTag];
    
    return SecItemDelete((__bridge CFDictionaryRef)sKeyDic);
}

+ (OSStatus)SecItemAddPublicKey:(NSString * _Nonnull)aPublicKey tag:(NSString * _Nonnull)aTag
{
    NSMutableDictionary *sPublicKeyDic = [[NSMutableDictionary alloc] init];
    NSData              *sTag          = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    NSData              *sKeyData      = [[self class] base64DecodeToData:aPublicKey];
                         sKeyData      = [[self class] stripPublicKeyHeader:sKeyData];
    
    [sPublicKeyDic setObject:(__bridge id)kSecClassKey              forKey:(__bridge id)kSecClass];
    [sPublicKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA        forKey:(__bridge id)kSecAttrKeyType];
    [sPublicKeyDic setObject:sTag                                   forKey:(__bridge id)kSecAttrApplicationTag];
    [sPublicKeyDic setObject:sKeyData                               forKey:(__bridge id)kSecValueData];
    [sPublicKeyDic setObject:(__bridge id) kSecAttrKeyClassPublic   forKey:(__bridge id)kSecAttrKeyClass];
    [sPublicKeyDic setObject:[NSNumber numberWithBool:YES]          forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef sPersistKey = NULL;
    OSStatus  sStatus     = SecItemAdd((__bridge CFDictionaryRef)sPublicKeyDic, &sPersistKey);
    if (sPersistKey){
        CFRelease(sPersistKey);
    }

    return sStatus;
}

+ (SecKeyRef)SecKeyCreateWithPublicKey:(NSString * _Nonnull)aPublicKey
{
    NSData       *sKeyData = [[self class] base64DecodeToData:aPublicKey];
    NSDictionary *sOptions = @{
                               (id)kSecAttrKeyType        : (id)kSecAttrKeyTypeRSA,
                               (id)kSecAttrKeyClass       : (id)kSecAttrKeyClassPublic,
                               (id)kSecAttrKeySizeInBits  : @(kRSAKeySize)
                               };
    
    CFErrorRef sError = NULL;
    SecKeyRef  sKey   = NULL;
    
    if (@available(iOS 10.0, *))
    {
        sKey = SecKeyCreateWithData((__bridge CFDataRef)sKeyData, (__bridge CFDictionaryRef)sOptions, &sError);
        if (sError)
        {
            NSLog(@"SecKeyCreateWithPublicKey Error: %@", (__bridge NSError *)sError);
            sKey = NULL;
        }
    }

    return sKey;
}

#pragma mark - get secKeyRef by a External private key string

+ (SecKeyRef)secExternalPrivateKeyFromString:(NSString * _Nonnull)aExternalPrivateKey
{
    SecKeyRef sSecKeyRef = NULL;
    
    if (@available(iOS 10.0, *))
    {
        sSecKeyRef = [[self class] SecKeyCreateWithPrivateKey:aExternalPrivateKey];
    }
    else
    {
        OSStatus  status = noErr;
        NSString *sTag   = kExternalPrivateKeyTag;
        
        status = [[self class] SecItemAddPrivateKey:aExternalPrivateKey tag:sTag];
        if ((status != errSecSuccess) && (status != errSecDuplicateItem)) {
            sSecKeyRef = NULL;
        }
    
        status = [[self class] secKeyRef:&sSecKeyRef tag:sTag];
        if(status != errSecSuccess){
            sSecKeyRef = NULL;
        }
        
        status = [[self class] SecItemDeleteByTag:sTag];
    }
    
    return sSecKeyRef;
}

+ (OSStatus)SecItemAddPrivateKey:(NSString * _Nonnull)aPrivateKey tag:(NSString * _Nonnull)aTag
{
    NSMutableDictionary *sPrivateKeyDic = [[NSMutableDictionary alloc] init];
    NSData              *sTag           = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    NSData              *sKeyData       = [[self class] base64DecodeToData:aPrivateKey];
                         sKeyData       = [[self class] stripPrivateKeyHeader:sKeyData];
    
    [sPrivateKeyDic setObject:(__bridge id)kSecClassKey              forKey:(__bridge id)kSecClass];
    [sPrivateKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA        forKey:(__bridge id)kSecAttrKeyType];
    [sPrivateKeyDic setObject:sTag                                   forKey:(__bridge id)kSecAttrApplicationTag];
    [sPrivateKeyDic setObject:sKeyData                               forKey:(__bridge id)kSecValueData];
    [sPrivateKeyDic setObject:(__bridge id)kSecAttrKeyClassPrivate   forKey:(__bridge id)kSecAttrKeyClass];
    [sPrivateKeyDic setObject:[NSNumber numberWithBool:YES]          forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef sPersistKey = NULL;
    OSStatus  sStatus     = SecItemAdd((__bridge CFDictionaryRef)sPrivateKeyDic, &sPersistKey);
    if (sPersistKey){
        CFRelease(sPersistKey);
    }
    
    return sStatus;
}

+ (SecKeyRef)SecKeyCreateWithPrivateKey:(NSString * _Nonnull)aPrivateKey
{
    NSData       *sKeyData = [[self class] base64DecodeToData:aPrivateKey];
                  sKeyData = [[self class] stripPrivateKeyHeader:sKeyData];
    NSDictionary *sOptions = @{
                               (id)kSecAttrKeyType        : (id)kSecAttrKeyTypeRSA,
                               (id)kSecAttrKeyClass       : (id)kSecAttrKeyClassPrivate,
                               (id)kSecAttrKeySizeInBits  : @(kRSAKeySize)
                               };
    
    CFErrorRef sError = NULL;
    SecKeyRef  sKey   = NULL;
    
    if (@available(iOS 10.0, *))
    {
        sKey = SecKeyCreateWithData((__bridge CFDataRef)sKeyData, (__bridge CFDictionaryRef)sOptions, &sError);
        if (sError)
        {
            NSLog(@"SecKeyCreateWithPrivateKey Error: %@", (__bridge NSError *)sError);
            sKey = NULL;
        }
    }
    
    return sKey;
}

#pragma mark - remove all keys

+ (void)removeAllRSAKeys
{
    OSStatus             sSearchResult = noErr;
    CFArrayRef           sArray        = NULL;
    NSMutableDictionary *sQueryDict    = [NSMutableDictionary dictionary];
    
    [sQueryDict setObject:(id)kSecClassKey          forKey:(id)kSecClass];
    [sQueryDict setObject:(id)kSecAttrKeyTypeRSA    forKey:(id)kSecAttrKeyType];
    [sQueryDict setObject:@(YES)                    forKey:(id)kSecReturnAttributes];
    [sQueryDict setObject:kRSALabel                 forKey:(id)kSecAttrLabel];
    [sQueryDict setObject:(id)kSecMatchLimitAll     forKey:(id)kSecMatchLimit];
    
    sSearchResult = SecItemCopyMatching((__bridge CFDictionaryRef)sQueryDict, (CFTypeRef *)&sArray);
    
    if (sSearchResult == errSecSuccess)
    {
        NSArray *sRSADicts = (__bridge NSArray *)sArray;
        
        for (NSDictionary *aRSADict in sRSADicts)
        {
            NSMutableDictionary *sDeleteDict = [NSMutableDictionary dictionaryWithDictionary:aRSADict];
            
            [sDeleteDict setObject:(id)kSecClassKey forKey:(id)kSecClass];
            
            SecItemDelete((__bridge CFDictionaryRef)sDeleteDict);
        }
    }
    
    if (sArray)
    {
        CFRelease(sArray);
    }
}

#pragma mark - generate key on iOS

+ (OSStatus)generateKeyPairForPublicSecKeyRef:(SecKeyRef *)aPublicKeyRef
                                 publicKeyTag:(NSString * _Nonnull)aPublicKeyTag
                             privateSecKeyRef:(SecKeyRef *)aPrivateKeyRef
                                privateKeyTag:(NSString * _Nonnull)aPrivateKeyTag
{
    NSMutableDictionary *sPublicKeyAttrs  = [NSMutableDictionary dictionary];
    NSMutableDictionary *sPrivateKeyAttrs = [NSMutableDictionary dictionary];
    NSMutableDictionary *sKeyPairAttrs    = [NSMutableDictionary dictionary];
    
    NSData              *sPublicTag       = [aPublicKeyTag  dataUsingEncoding:NSUTF8StringEncoding];
    NSData              *sPrivateTag      = [aPrivateKeyTag dataUsingEncoding:NSUTF8StringEncoding];
    
    [sPublicKeyAttrs  setObject:sPublicTag             forKey:(id)kSecAttrApplicationTag];
    [sPrivateKeyAttrs setObject:sPrivateTag            forKey:(id)kSecAttrApplicationTag];
    
    [sKeyPairAttrs    setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [sKeyPairAttrs    setObject:@(kRSAKeySize)         forKey:(id)kSecAttrKeySizeInBits];
    [sKeyPairAttrs    setObject:@(YES)                 forKey:(id)kSecAttrIsPermanent];
    [sKeyPairAttrs    setObject:kRSALabel              forKey:(id)kSecAttrLabel];
    [sKeyPairAttrs    setObject:sPublicKeyAttrs        forKey:(id)kSecPublicKeyAttrs];
    [sKeyPairAttrs    setObject:sPrivateKeyAttrs       forKey:(id)kSecPrivateKeyAttrs];
    
    return SecKeyGeneratePair((__bridge CFDictionaryRef)sKeyPairAttrs, aPublicKeyRef, aPrivateKeyRef);
}

+ (OSStatus)generateKeyPairForPublicSecKeyRef:(SecKeyRef *)aPublicKeyRef privateSecKeyRef:(SecKeyRef *)aPrivateKeyRef
{
    return [[self class] generateKeyPairForPublicSecKeyRef:aPublicKeyRef publicKeyTag:kiOSPublicKeyTag privateSecKeyRef:aPrivateKeyRef privateKeyTag:kiOSPrivateKeyTag];
}

+ (OSStatus)generateKeyPair
{
    return [[self class] generateKeyPairForPublicSecKeyRef:nil privateSecKeyRef:nil];
}

+ (OSStatus)generateKeyPairWithPublicKeyTag:(NSString * _Nonnull)aPublicKeyTag privateKeyTag:(NSString * _Nonnull)aPrivateKeyTag
{
    return [[self class] generateKeyPairForPublicSecKeyRef:nil publicKeyTag:aPublicKeyTag privateSecKeyRef:nil privateKeyTag:aPrivateKeyTag];
}

#pragma mark - get a key by a tag

+ (NSString *)publicKeyStringByTag:(nonnull NSString *)aPublicKeyTag
{
    SecKeyRef sPublicKeyRef = NULL;
    NSData   *sPublicKeyData;
    NSString *sPublicKeyString;
    OSStatus  status = noErr;
    
    status = [[self class] secKeyRef:&sPublicKeyRef tag:aPublicKeyTag];
    
    if (status != errSecSuccess || !sPublicKeyRef)
    {
        return nil;
    }
    
    sPublicKeyData    = [[self class] dataFromKey:sPublicKeyRef];
    sPublicKeyString  = [[self class] base64EncodeWithData:sPublicKeyData];
    
    return [[self class] convertPublicKey:sPublicKeyString];
}

+ (NSString *)iOSPublicKeyString
{
    return [[self class] publicKeyStringByTag:kiOSPublicKeyTag];
}

+ (OSStatus)secKeyRef:(SecKeyRef * _Nonnull)aKeyRef tag:(NSString * _Nonnull)aTag
{
    NSMutableDictionary *sQueryDict = [NSMutableDictionary dictionary];
    
    [sQueryDict setObject:(id)kSecClassKey          forKey:(id)kSecClass];
    [sQueryDict setObject:(id)kSecAttrKeyTypeRSA    forKey:(id)kSecAttrKeyType];
    [sQueryDict setObject:@(YES)                    forKey:(id)kSecReturnRef];
    [sQueryDict setObject:aTag                      forKey:(id)kSecAttrApplicationTag];
    
    return SecItemCopyMatching((__bridge CFDictionaryRef)sQueryDict, (CFTypeRef *)aKeyRef);
}

#pragma mark - convert

+ (NSData *)dataFromKey:(SecKeyRef _Nonnull)aKey
{
    NSData *sResult;
    
    if (@available(iOS 10.0, *))
    {
        CFDataRef sData = SecKeyCopyExternalRepresentation(aKey, NULL);
        sResult = (__bridge NSData *)sData;
    }
    else
    {
        sResult = [[self class] transformSecKeyRefToData:aKey];
    }
    
    return sResult;
}

+ (NSData *)transformSecKeyRefToData:(SecKeyRef _Nonnull)key
{
    NSData *publicKeyData;
    OSStatus putResult, delResult = noErr;
    
    // Params for putting the key first
    NSMutableDictionary *putKeyParams = [NSMutableDictionary new];
    putKeyParams[(__bridge id) kSecClass]               = (__bridge id) kSecClassKey;
    putKeyParams[(__bridge id) kSecAttrApplicationTag]  = kTransformSecKeyRefToData;
    putKeyParams[(__bridge id) kSecValueRef]            = (__bridge id) (key);
    putKeyParams[(__bridge id) kSecReturnData]          = (__bridge id) (kCFBooleanTrue); // Request the key's data to be returned too
    
    // Params for deleting the data
    NSMutableDictionary *delKeyParams = [[NSMutableDictionary alloc] init];
    delKeyParams[(__bridge id) kSecClass]               = (__bridge id) kSecClassKey;
    delKeyParams[(__bridge id) kSecAttrApplicationTag]  = kTransformSecKeyRefToData;
    delKeyParams[(__bridge id) kSecReturnData]          = (__bridge id) (kCFBooleanTrue);
    
    // Put the key
    putResult = SecItemAdd((__bridge CFDictionaryRef) putKeyParams, (void *)&publicKeyData);
    // Delete the key
    delResult = SecItemDelete((__bridge CFDictionaryRef)(delKeyParams));
    
    if ((putResult != errSecSuccess) || (delResult != errSecSuccess))
    {
        publicKeyData = nil;
    }
    
    return publicKeyData;
}


#pragma mark - RSA Encrypt / Decrypt

+ (NSData *)RSAEncryptData:(NSData * _Nonnull)aData Key:(SecKeyRef _Nonnull)aKey
{
    NSData   *sEncryptData   = nil;
    size_t    sBufferLength  = SecKeyGetBlockSize(aKey);
    uint8_t  *sBuffer        = malloc(sBufferLength);
    
    OSStatus  sResult        = SecKeyEncrypt(aKey,
                                             kSecPaddingPKCS1,
                                             aData.bytes,
                                             aData.length,
                                             sBuffer,
                                             &sBufferLength);
    
    if (sResult == errSecSuccess)
    {
        sEncryptData = [NSData dataWithBytes:sBuffer length:sBufferLength];
    }
    
    free(sBuffer);
    CFRelease(aKey);
    return sEncryptData;
}

+ (NSData *)RSADecryptData:(NSData * _Nonnull)aData Key:(SecKeyRef _Nonnull)aKey
{
    NSData   *sDecryptData   = nil;
    size_t    sBufferLength  = SecKeyGetBlockSize(aKey);
    uint8_t  *sBuffer        = malloc(sBufferLength);
    
    OSStatus  sResult        = SecKeyDecrypt(aKey,
                                             kSecPaddingPKCS1,
                                             aData.bytes,
                                             aData.length,
                                             sBuffer,
                                             &sBufferLength);
    
    if (sResult == errSecSuccess)
    {
        sDecryptData = [NSData dataWithBytes:sBuffer length:sBufferLength];
    }
    
    free(sBuffer);
    CFRelease(aKey);
    return sDecryptData;
    
}

#pragma mark - RSA format

+ (NSData *)stripPublicKeyHeader:(NSData * _Nonnull)aKey
{
    // Skip ASN.1 public key header
    if (aKey == nil) return(nil);
    
    unsigned long len = [aKey length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[aKey bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

//credit: http://hg.mozilla.org/services/fx-home/file/tip/Sources/NetworkAndStorage/CryptoUtils.m#l1036
+ (NSData *)stripPrivateKeyHeader:(NSData * _Nonnull)aKey
{
    // Skip ASN.1 private key header
    if (aKey == nil) return(nil);
    
    unsigned long len = [aKey length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[aKey bytes];
    unsigned int  idx     = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    // Now make a new NSData from this buffer
    return [aKey subdataWithRange:NSMakeRange(idx, c_len)];
}

// https://blog.wingsofhermes.org/?p=42
+ (NSString *)convertPublicKey:(NSString * _Nonnull)aPublicKeyOniOS
{
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    NSData *publicKeyBits = [[self class] base64DecodeToData:aPublicKeyOniOS];
    
    // OK - that gives us the "BITSTRING component of a full DER
    // encoded RSA public key - we now need to build the rest
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([publicKeyBits length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (int)(([publicKeyBits length ] +1 ) / 256 ) + 2 ;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [publicKeyBits length];
    size_t j = [[self class] encodeLength:&builder[1] size:i];
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = [[self class] encodeLength:&builder[1] size:[publicKeyBits length] + 1];
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:publicKeyBits];
    
    // Now translate the result to a Base64 string
    NSString * ret = [[self class] base64EncodeWithData:encKey];
    
    return ret;
}

+ (size_t)encodeLength:(unsigned char *)aBuf size:(size_t)aLength
{
    // encode length in ASN.1 DER format
    if (aLength < 128) {
        aBuf[0] = aLength;
        return 1;
    }
    
    size_t i = (aLength / 256) + 1;
    aBuf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j)
    {
        aBuf[i - j] = aLength & 0xFF;
        aLength = aLength >> 8;
    }
    
    return i + 1;
}


#pragma mark - base64


+ (NSString *)base64EncodeWithData:(NSData * _Nonnull)aData
{
    aData = [aData base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:aData encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSData *)base64DecodeToData:(NSString * _Nonnull)aStr
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:aStr options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

@end
