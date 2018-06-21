//
//  RSAManager.m
//  RSAClient-iOS
//
//  Created by tigi on 2018. 4. 27..
//  Copyright © 2018년 tigi. All rights reserved.
//

#import "RSAManager.h"

static NSString *const kServerPublicKeyTag    = @"RSA_SERVER_PUBLICKEY";
static NSString *const kServerPrivateKeyTag   = @"RSA_SERVER_PRIVATEKEY";

static NSString *const kRSALabel              = @"RSALabel";

static NSString *const kiOSPublicKeyTag       = @"RSA_IOS_PUBLICKEY";
static NSString *const kiOSPrivateKeyTag      = @"RSA_IOS_PRIVATEKEY";

static int       const kRSAKeySize            = 2048;

@implementation RSAManager

#pragma mark - encrypt

+ (NSString *)encryptString:(NSString * _Nonnull)aPlanString publicKey:(NSString * _Nonnull)aPublicKeyString tag:(NSString *)aTag
{
    SecKeyRef   sPublicKeyRef = NULL;
    NSData     *sPlainData;
    NSData     *sCipherData;
    
    if (!aPlanString || !aPublicKeyString)
    {
        return nil;
    }
    
    sPublicKeyRef = [[self class] secPublicKeyFromString:aPublicKeyString tag:aTag];
    if (!sPublicKeyRef)
    {
        return nil;
    }
    
    sPlainData    = [aPlanString dataUsingEncoding:NSUTF8StringEncoding];
    sCipherData   = [[self class] RSAEncryptData:sPlainData Key:sPublicKeyRef];
    
    return base64EncodeWithData(sCipherData);
}

+ (NSString *)iOSKeyEncryptString:(NSString * _Nonnull)aPlanString tag:(NSString * _Nonnull)aPublicKeyTag
{
    SecKeyRef   sPublicKeyRef = NULL;
    NSData     *sPlainData;
    NSData     *sCipherData;
    
    [[self class] secKeyRef:&sPublicKeyRef tag:aPublicKeyTag];
    if (!sPublicKeyRef)
    {
        return nil;
    }
    
    sPlainData  = [aPlanString dataUsingEncoding:NSUTF8StringEncoding];
    sCipherData = [[self class] RSAEncryptData:sPlainData Key:sPublicKeyRef];
    
    return base64EncodeWithData(sCipherData);
}

+ (NSString *)iOSKeyEncryptString:(NSString * _Nonnull)aPlanString
{
    return [[self class] iOSKeyEncryptString:aPlanString tag:kiOSPublicKeyTag];
}


#pragma mark - decrypt

+ (NSString *)decryptString:(NSString * _Nonnull)aEncryptedString privateKey:(NSString * _Nonnull)aPrivateKeyString tag:(NSString *)aTag
{
    SecKeyRef   sPrivateKeyRef = NULL;
    NSData     *sPlainData;
    NSData     *sCipherData;
    
    if (!aEncryptedString || !aPrivateKeyString)
    {
        return nil;
    }
    
    sPrivateKeyRef = [[self class] secPrivateKeyFromString:aPrivateKeyString tag:aTag];
    if (!sPrivateKeyRef)
    {
        return nil;
    }
    
    sCipherData    = base64DecodeToData(aEncryptedString);
    sPlainData     = [[self class] RSADecryptData:sCipherData Key:sPrivateKeyRef];

    return [[NSString alloc] initWithData:sPlainData encoding:NSUTF8StringEncoding];
}

+ (NSString *)iOSKeyDecryptString:(nonnull NSString *)aEncryptedString tag:(nonnull NSString *)aPrivateKeyTag
{
    SecKeyRef   sPrivateKeyRef = NULL;
    NSData     *sPlainData;
    NSData     *sCipherData;
    
    [[self class] secKeyRef:&sPrivateKeyRef tag:aPrivateKeyTag];
    if (!sPrivateKeyRef)
    {
        return nil;
    }
    
    sCipherData = base64DecodeToData(aEncryptedString);
    sPlainData  = [[self class] RSADecryptData:sCipherData Key:sPrivateKeyRef];
    
    return [[NSString alloc] initWithData:sPlainData encoding:NSUTF8StringEncoding];
}

+ (NSString *)iOSKeyDecryptString:(NSString * _Nonnull)aEncryptedString
{
    return [[self class] iOSKeyDecryptString:aEncryptedString tag:kiOSPrivateKeyTag];
}



#pragma mark - get secKeyRef by a public key string

+ (SecKeyRef)secPublicKeyFromString:(NSString *)aKey tag:(NSString *)aTag
{
    SecKeyRef sSecKeyRef = NULL;
    
    if (@available(iOS 10.0, *))
    {
        sSecKeyRef = [[self class] SecKeyCreateWithPublicKey:aKey];
    }
    else
    {
        if (!aTag)
        {
            aTag = kServerPublicKeyTag;
        }
        
        [[self class] SecItemDeleteByTag:aTag];
        
        OSStatus status = [[self class] SecItemAddPublicKey:aKey tag:aTag];
        if ((status != noErr) && (status != errSecDuplicateItem)) {
            return NULL;
        }
        
        status = [[self class] secKeyRef:&sSecKeyRef tag:aTag];
        if(status != noErr){
            return NULL;
        }
    }
    
    return sSecKeyRef;
}

+ (OSStatus)SecItemDeleteByTag:(NSString *)aTag
{
    NSMutableDictionary *sKeyDic = [[NSMutableDictionary alloc] init];
    NSData              *sTag    = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    
    [sKeyDic setObject:(__bridge id)kSecClassKey             forKey:(__bridge id)kSecClass];
    [sKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA       forKey:(__bridge id)kSecAttrKeyType];
    [sKeyDic setObject:sTag                                  forKey:(__bridge id)kSecAttrApplicationTag];
    
    return SecItemDelete((__bridge CFDictionaryRef)sKeyDic);
}

+ (OSStatus)SecItemAddPublicKey:(NSString *)aPublicKey tag:(NSString *)aTag
{
    NSMutableDictionary *sPublicKeyDic = [[NSMutableDictionary alloc] init];
    NSData              *sTag          = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    NSData              *sKeyData      = base64DecodeToData(aPublicKey);
    
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

+ (SecKeyRef)SecKeyCreateWithPublicKey:(NSString *)aPublicKey
{
    NSData       *sKeyData = base64DecodeToData(aPublicKey);
    NSDictionary *sOptions = @{
                               (id)kSecAttrKeyType        : (id)kSecAttrKeyTypeRSA,
                               (id)kSecAttrKeyClass       : (id)kSecAttrKeyClassPublic,
                               (id)kSecAttrKeySizeInBits  : @(kRSAKeySize)
                               };
    
    CFErrorRef sError = NULL;
    SecKeyRef  sKey   = SecKeyCreateWithData((__bridge CFDataRef)sKeyData, (__bridge CFDictionaryRef)sOptions, &sError);
    if (sError)
    {
        NSLog(@"SecKeyCreateWithPublicKey Error: %@", (__bridge NSError *)sError);
        sKey = NULL;
    }
    
    return sKey;
}

#pragma mark - get secKeyRef by a private key string

+ (SecKeyRef)secPrivateKeyFromString:(NSString *)aKey tag:(NSString *)aTag
{
    SecKeyRef sSecKeyRef = NULL;
    
    if (@available(iOS 10.0, *))
    {
        sSecKeyRef = [[self class] SecKeyCreateWithPrivateKey:aKey];
    }
    else
    {
        if (!aTag)
        {
            aTag = kServerPrivateKeyTag;
        }
        
        [[self class] SecItemDeleteByTag:aTag];
        
        OSStatus status = [[self class] SecItemAddPrivateKey:aKey tag:aTag];
        if ((status != noErr) && (status != errSecDuplicateItem)) {
            sSecKeyRef = NULL;
        }
    
        status = [[self class] secKeyRef:&sSecKeyRef tag:aTag];
        if(status != noErr){
            sSecKeyRef = NULL;
        }
    }
    
    return sSecKeyRef;
}

+ (OSStatus)SecItemAddPrivateKey:(NSString *)aPrivateKey tag:(NSString *)aTag
{
    NSMutableDictionary *sPrivateKeyDic = [[NSMutableDictionary alloc] init];
    NSData              *sTag           = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    NSData              *sKeyData       = base64DecodeToData(aPrivateKey);
                         sKeyData       = stripPrivateKeyHeader(sKeyData);
    
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

+ (SecKeyRef)SecKeyCreateWithPrivateKey:(NSString *)aPrivateKey
{
    NSData       *sKeyData = base64DecodeToData(aPrivateKey);
                  sKeyData = stripPrivateKeyHeader(sKeyData);
    NSDictionary *sOptions = @{
                               (id)kSecAttrKeyType        : (id)kSecAttrKeyTypeRSA,
                               (id)kSecAttrKeyClass       : (id)kSecAttrKeyClassPrivate,
                               (id)kSecAttrKeySizeInBits  : @(kRSAKeySize)
                               };
    
    CFErrorRef sError = NULL;
    SecKeyRef  sKey   = SecKeyCreateWithData((__bridge CFDataRef)sKeyData, (__bridge CFDictionaryRef)sOptions, &sError);
    if (sError)
    {
        NSLog(@"SecKeyCreateWithPrivateKey Error: %@", (__bridge NSError *)sError);
        sKey = NULL;
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

+ (OSStatus)generateKeyPairForPublicSecKeyRef:(SecKeyRef *)  aPublicKeyRef
                                 publicKeyTag:(NSString *)   aPublicKeyTag
                             privateSecKeyRef:(SecKeyRef *)  aPrivateKeyRef
                                privateKeyTag:(NSString *)   aPrivateKeyTag
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

+ (NSString *)iOSPublicKeyStringForServerByTag:(nonnull NSString *)aPublicKeyTag
{
    SecKeyRef sPublicKeyRef = NULL;
    NSData   *sPublicKeyData;
    NSString *sPublicKeyString;
    
    [[self class] secKeyRef:&sPublicKeyRef tag:aPublicKeyTag];
    
    if (!sPublicKeyRef)
    {
        [[self class] removeAllRSAKeys];
        [[self class] generateKeyPairForPublicSecKeyRef:&sPublicKeyRef privateSecKeyRef:nil];
    }
    
    sPublicKeyData    = [[self class] dataFromKey:sPublicKeyRef];
    sPublicKeyString  = base64EncodeWithData(sPublicKeyData);
    
    return convertPublicKeyForServer(sPublicKeyString);
}

+ (NSString *)iOSPublicKeyStringForServer
{
    return [[self class] iOSPublicKeyStringForServerByTag:kiOSPublicKeyTag];
}

+ (OSStatus)secKeyRef:(SecKeyRef *)aKeyRef tag:(NSString *)aTag
{
    NSMutableDictionary *sQueryDict = [NSMutableDictionary dictionary];
    
    [sQueryDict setObject:(id)kSecClassKey          forKey:(id)kSecClass];
    [sQueryDict setObject:(id)kSecAttrKeyTypeRSA    forKey:(id)kSecAttrKeyType];
    [sQueryDict setObject:@(YES)                    forKey:(id)kSecReturnRef];
    [sQueryDict setObject:aTag                      forKey:(id)kSecAttrApplicationTag];
    
    return SecItemCopyMatching((__bridge CFDictionaryRef)sQueryDict, (CFTypeRef *)aKeyRef);
}

#pragma mark - convert

+ (NSData *)dataFromKey:(SecKeyRef)aKey
{
    CFDataRef sData = SecKeyCopyExternalRepresentation(aKey, NULL);
    
    return (__bridge NSData *)sData;
}

#pragma mark - RSA Encrypt / Decrypt

+ (NSData *)RSAEncryptData:(NSData *)aData Key:(SecKeyRef)aKey
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
        sEncryptData = [NSData dataWithBytesNoCopy:sBuffer length:sBufferLength];
    }
    
    return sEncryptData;
}

+ (NSData *)RSADecryptData:(NSData *)aData Key:(SecKeyRef)aKey
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
        sDecryptData = [NSData dataWithBytesNoCopy:sBuffer length:sBufferLength];
    }
    
    return sDecryptData;
    
}

#pragma mark - RSA format

//credit: http://hg.mozilla.org/services/fx-home/file/tip/Sources/NetworkAndStorage/CryptoUtils.m#l1036
NSData *stripPrivateKeyHeader(NSData *d_key)
{
    // Skip ASN.1 private key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
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
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

// https://blog.wingsofhermes.org/?p=42
NSString *convertPublicKeyForServer(NSString *aPublicKeyOniOS)
{
    
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    NSData *publicKeyBits = base64DecodeToData(aPublicKeyOniOS);
    
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
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [publicKeyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:publicKeyBits];
    
    // Now translate the result to a Base64 string
    NSString * ret = base64EncodeWithData(encKey);
    
    return ret;
}

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {         buf[i - j] = length & 0xFF;         length = length >> 8;
    }
    
    return i + 1;
}

#pragma mark - base64

NSString *base64EncodeWithData(NSData *data){
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

NSData *base64DecodeToData(NSString *str){
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

@end
