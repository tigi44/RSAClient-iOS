//
//  RSAManager.m
//  RSAClient-iOS
//
//  Created by tigi on 2018. 4. 27..
//  Copyright © 2018년 tigi. All rights reserved.
//

#import "RSAManager.h"

static NSString * const kServerPublicKeyString = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhHOx/thUgKvWp5/cyE6HXbfYBqSVDArBA/NCmY6SsrdWcAc1aXUh2Ho/H3jpQSvkqfqGrfykcNP4Z/WjsLMp3Iyw+dXnOuIZbezuAuB0DIZLMLGlu42HPKQIrE+AaxF7ISLVQrc9LVjzjjNtj+SeYKxP+3+1DNk4jBTP1IraN//zaxND2Kz3iQUJszIXZNeVPG+mUqBqxsJBV0Ejp7BqaziCpnF/4CqSC11+D6Inm0ItwUa5lQZhViSr4689fhYt3Hy7LSsBAJ4Rcv+4HQRM9R4IIE1KBTYUhHTO7SSM8U06PyAwWfUJ9WVoPYqtHgP4BludRk6iTS2Yzwo9FeeWbQIDAQAB";
static NSString * const kServerPrivateKeyString = @"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCEc7H+2FSAq9ann9zIToddt9gGpJUMCsED80KZjpKyt1ZwBzVpdSHYej8feOlBK+Sp+oat/KRw0/hn9aOwsyncjLD51ec64hlt7O4C4HQMhkswsaW7jYc8pAisT4BrEXshItVCtz0tWPOOM22P5J5grE/7f7UM2TiMFM/Uito3//NrE0PYrPeJBQmzMhdk15U8b6ZSoGrGwkFXQSOnsGprOIKmcX/gKpILXX4PoiebQi3BRrmVBmFWJKvjrz1+Fi3cfLstKwEAnhFy/7gdBEz1HgggTUoFNhSEdM7tJIzxTTo/IDBZ9Qn1ZWg9iq0eA/gGW51GTqJNLZjPCj0V55ZtAgMBAAECggEADD/a7VO6dO/veS8qrwe8Mymme+7KrgNsmF3uAd+Sp56XCuNPyEIB8FBV+CYphFJ34lR+Eic0Wg7wgUTRb60SKQiF8YUbznFMosLvvCpf8SyWVZmIV1Eeebg96RmtKbnDJmxfRr1FliUM2VDeSBl/oDcvanYEG30XYrUmB2UUC2upWnAzYo1h3zDkZBKR2mAr7IiUTGnFZjdG+yG6x0dSoE+KGR47F9QqZ+ofUxCJmHH4NcKJ0G6tsf9TN8Dtum/Am3TMp5THq1ZwQ7K+T9LBP4z9SGA9MOpmAMwUKk4ve/3UBDro3ENQqePFgRB0Pn/3MqAGGN9rNH6ohyLC+/IyLQKBgQC6dMwq3yXaotd/D0yxvV2ZcIu2k+b7Nav0CvudXkKp375wWr+KwpLcveS7JxdMp4DZqiW6pwi/BXw1oBx1zIM85D37MxpXfNDrb8IwiB+giPycdTqyoEFx3Byy67FSOcLcvvYp0H2rp+zVKIiA1X1nN6+EfrXpB+Nfp/ss6HWEcwKBgQC12nZThqb77gtDN/B3ZWqYuGXSunSY1UWOnyc+hn/gPP427gqP9HFN/KZIdGVSGqyP87PUm/H4npW95R/qppJuvlIXAwBDdvTpGctyRSWBM2VYWbOeOvJmdhQRF5wfuEmdfNSeNCO94HsB9jgjoGmaigcAyxSaMAzk0D/B92qhnwKBgEpS/H+qa+B3QQd5Bc1j+seLQWYKFuzUPDMPnbThOhmVAsiuo+OgJAKx/1dLAdKggpBBbsC0jJv4h8aoiC+80iOXp81WVY3CR1VSO0o1OMY5VNjZMgi6MNw+LYJ0yT5JoA92X5HTdgTS72kYuzD/6PkYDXL3P3QgnNYok8sW7qFZAoGAEWjCnyhq3/9f8KVwTd3VoJ02kj/rXZ49NHQkC6ZQo6TzKUsMk89w8WhYeuM5t+x5zKYl9xqexZBZAX7n2UztA9EQhsdwxQSkWZRwl5XrCz1iXFzqByHZhtmS/jfmaFr6ISuMJ0ESkuDkpcFuimqW8YZ5OSg35rLm6RjOocEP4j0CgYBWByb6sgiOLQzc2JU+Is4Lm5NxDhpfqT0D+A52uCfTX4GuqPGrgHgcOEivAuc/161o3kpiqowpkh4O/uWgdiFej7nlJRRBr5DetzZvHKCe+datr6Ywmd5jwRlIX7FEHoyQE4GFPpQ1xdMUqoH39ntPUoc2+d9cyLLpTiESYgnCzA==";


static NSString *const kServerPublicKeyTag    = @"RSA_SERVER_PUBLICKEY";
static NSString *const kServerPrivateKeyTag   = @"RSA_SERVER_PRIVATEKEY";

static NSString *const kRSALabel         = @"RSALabel";

static NSString *const kiOSPublicKeyTag       = @"RSA_IOS_PUBLICKEY";
static NSString *const kiOSPrivateKeyTag      = @"RSA_IOS_PRIVATEKEY";

@implementation RSAManager

#pragma mark - encrypt

+ (NSString *)encryptString:(NSString * _Nonnull)aPlanString publicKey:(NSString * _Nonnull)aPublicKeyString tag:(NSString *)aTag
{
    SecKeyRef   sPublicKeyRef;
    NSData      *sPlainData;
    NSData      *sCipherData;
    
    if (!aPlanString || !aPublicKeyString)
    {
        return nil;
    }
    
    if (!aTag)
    {
        aTag = kServerPublicKeyTag;
    }
    
    sPublicKeyRef = [[self class] secPublicKeyFromString:aPublicKeyString tag:aTag];
    
    sPlainData = [aPlanString dataUsingEncoding:NSUTF8StringEncoding];
    sCipherData = [[self class] RSAEncryptData:sPlainData Key:sPublicKeyRef];
    
    return base64_encode_data(sCipherData);
}

+ (NSString *)serverKeyEncryptString:(NSString * _Nonnull)aPlanString
{
    return [[self class] encryptString:aPlanString publicKey:kServerPublicKeyString tag:kServerPublicKeyTag];
}

+ (NSString *)iOSKeyEncryptString:(NSString * _Nonnull)aPlanString
{
    SecKeyRef   sPublicKeyRef;
    NSData      *sPlainData;
    NSData      *sCipherData;
    
    [[self class] secKeyRef:&sPublicKeyRef tag:kiOSPublicKeyTag];
    
    sPlainData = [aPlanString dataUsingEncoding:NSUTF8StringEncoding];
    sCipherData = [[self class] RSAEncryptData:sPlainData Key:sPublicKeyRef];
    
    return base64_encode_data(sCipherData);
}


#pragma mark - decrypt

+ (NSString *)decryptString:(NSString * _Nonnull)aEncryptedString privateKey:(NSString * _Nonnull)aPrivateKeyString tag:(NSString *)aTag
{
    SecKeyRef   sPrivateKeyRef;
    NSData      *sPlainData;
    NSData      *sCipherData;
    
    if (!aEncryptedString || !aPrivateKeyString)
    {
        return nil;
    }
    
    if (!aTag)
    {
        aTag = kServerPrivateKeyTag;
    }
    
    sPrivateKeyRef = [[self class] secPrivateKeyFromString:aPrivateKeyString tag:aTag];
    
    sCipherData = base64_decode(aEncryptedString);
    sPlainData = [[self class] RSADecryptData:sCipherData Key:sPrivateKeyRef];

    return [[NSString alloc] initWithData:sPlainData encoding:NSUTF8StringEncoding];
}

+ (NSString *)serverKeyDecryptString:(NSString * _Nonnull)aEncryptedString
{
    return [[self class] decryptString:aEncryptedString privateKey:kServerPrivateKeyString tag:kServerPrivateKeyTag];
}

+ (NSString *)iOSKeyDecryptString:(NSString * _Nonnull)aEncryptedString
{
    SecKeyRef   sPrivateKeyRef;
    NSData      *sPlainData;
    NSData      *sCipherData;
    
    [[self class] secKeyRef:&sPrivateKeyRef tag:kiOSPrivateKeyTag];
    
    sCipherData = base64_decode(aEncryptedString);
    sPlainData = [[self class] RSADecryptData:sCipherData Key:sPrivateKeyRef];
    
    return [[NSString alloc] initWithData:sPlainData encoding:NSUTF8StringEncoding];
}



#pragma mark - get secKeyRef by a public key string

+ (SecKeyRef)secPublicKeyFromString:(NSString *)aKey tag:(NSString *)aTag
{
    // delete
    [[self class] SecItemDeleteByTag:aTag];
    
    // add
    OSStatus status = [[self class] SecItemAddPublicKey:aKey tag:aTag];
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    // match
    SecKeyRef sKeyRef = nil;
    status = [[self class] secKeyRef:&sKeyRef tag:aTag];
    
    if(status != noErr){
        return nil;
    }
    
    return sKeyRef;
}

+ (OSStatus)SecItemDeleteByTag:(NSString *)aTag
{
    NSMutableDictionary *sKeyDic = [[NSMutableDictionary alloc] init];
    NSData *d_tag = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    
    [sKeyDic setObject:(__bridge id)kSecClassKey             forKey:(__bridge id)kSecClass];
    [sKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA       forKey:(__bridge id)kSecAttrKeyType];
    [sKeyDic setObject:d_tag                                  forKey:(__bridge id)kSecAttrApplicationTag];
    
    return SecItemDelete((__bridge CFDictionaryRef)sKeyDic);
}

+ (OSStatus)SecItemAddPublicKey:(NSString *)aPublicKey tag:(NSString *)aTag
{
    NSMutableDictionary *sPublicKeyDic = [[NSMutableDictionary alloc] init];
    NSData *d_tag = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    NSData *sKeyData = base64_decode(aPublicKey);
    
    [sPublicKeyDic setObject:(__bridge id)kSecClassKey             forKey:(__bridge id)kSecClass];
    [sPublicKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA       forKey:(__bridge id)kSecAttrKeyType];
    [sPublicKeyDic setObject:d_tag                                  forKey:(__bridge id)kSecAttrApplicationTag];
    [sPublicKeyDic setObject:sKeyData                               forKey:(__bridge id)kSecValueData];
    [sPublicKeyDic setObject:(__bridge id) kSecAttrKeyClassPublic   forKey:(__bridge id)kSecAttrKeyClass];
    [sPublicKeyDic setObject:[NSNumber numberWithBool:YES]          forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus sStatus = SecItemAdd((__bridge CFDictionaryRef)sPublicKeyDic, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    
    return sStatus;
}

#pragma mark - get secKeyRef by a private key string

+ (SecKeyRef)secPrivateKeyFromString:(NSString *)aKey tag:(NSString *)aTag
{
    // delete
    [[self class] SecItemDeleteByTag:aTag];
    
    // add
    OSStatus status = [[self class] SecItemAddPrivateKey:aKey tag:aTag];
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    // match
    SecKeyRef sKeyRef = nil;
    status = [[self class] secKeyRef:&sKeyRef tag:aTag];
    if(status != noErr){
        return nil;
    }
    
    return sKeyRef;
}

+ (OSStatus)SecItemAddPrivateKey:(NSString *)aPrivateKey tag:(NSString *)aTag
{
    NSMutableDictionary *sPrivateKeyDic = [[NSMutableDictionary alloc] init];
    NSData *d_tag = [NSData dataWithBytes:[aTag UTF8String] length:[aTag length]];
    NSData *sKeyData = base64_decode(aPrivateKey);
    sKeyData = stripPrivateKeyHeader(sKeyData);
    
    [sPrivateKeyDic setObject:(__bridge id)kSecClassKey             forKey:(__bridge id)kSecClass];
    [sPrivateKeyDic setObject:(__bridge id)kSecAttrKeyTypeRSA       forKey:(__bridge id)kSecAttrKeyType];
    [sPrivateKeyDic setObject:d_tag                                  forKey:(__bridge id)kSecAttrApplicationTag];
    [sPrivateKeyDic setObject:sKeyData                               forKey:(__bridge id)kSecValueData];
    [sPrivateKeyDic setObject:(__bridge id)kSecAttrKeyClassPrivate   forKey:(__bridge id)kSecAttrKeyClass];
    [sPrivateKeyDic setObject:[NSNumber numberWithBool:YES]          forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus sStatus = SecItemAdd((__bridge CFDictionaryRef)sPrivateKeyDic, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    
    return sStatus;
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
    [sQueryDict setObject:kRSALabel            forKey:(id)kSecAttrLabel];
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
    
    if (sArray != nil)
    {
        CFRelease(sArray);
    }
}

#pragma mark - generate key on iOS

+ (OSStatus)generateKeyPairWithPublicKey:(SecKeyRef *)  aPublicKeyRef
                            publicKeyTag:(NSString *)   aPublicKeyTag
                              privateKey:(SecKeyRef *)  aPrivateKeyRef
                           privateKeyTag:(NSString *)   aPrivateKeyTag
{
    NSMutableDictionary *sPublicKeyAttrs  = [NSMutableDictionary dictionary];
    NSMutableDictionary *sPrivateKeyAttrs = [NSMutableDictionary dictionary];
    NSMutableDictionary *sKeyPairAttrs    = [NSMutableDictionary dictionary];
    
    NSData *sPublicTag  = [aPublicKeyTag  dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sPrivateTag = [aPrivateKeyTag dataUsingEncoding:NSUTF8StringEncoding];
    
    [sPublicKeyAttrs  setObject:sPublicTag   forKey:(id)kSecAttrApplicationTag];
    [sPrivateKeyAttrs setObject:sPrivateTag  forKey:(id)kSecAttrApplicationTag];
    
    [sKeyPairAttrs setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [sKeyPairAttrs setObject:@(2048)                forKey:(id)kSecAttrKeySizeInBits];
    [sKeyPairAttrs setObject:@(YES)                 forKey:(id)kSecAttrIsPermanent];
    [sKeyPairAttrs setObject:kRSALabel         forKey:(id)kSecAttrLabel];
    [sKeyPairAttrs setObject:sPublicKeyAttrs        forKey:(id)kSecPublicKeyAttrs];
    [sKeyPairAttrs setObject:sPrivateKeyAttrs       forKey:(id)kSecPrivateKeyAttrs];
    
    return SecKeyGeneratePair((__bridge CFDictionaryRef)sKeyPairAttrs, aPublicKeyRef, aPrivateKeyRef);
}

+ (OSStatus)generateKeyPairWithPublicKey:(SecKeyRef *)aPublicKeyRef privateKey:(SecKeyRef *)aPrivateKeyRef
{
    return [[self class] generateKeyPairWithPublicKey:aPublicKeyRef publicKeyTag:kiOSPublicKeyTag privateKey:aPrivateKeyRef privateKeyTag:kiOSPrivateKeyTag];
}

+ (OSStatus)generateKeyPairWithPublicKey
{
    return [[self class] generateKeyPairWithPublicKey:nil privateKey:nil];
}

#pragma mark - get a key by a tag

+ (NSString *)iOSPublicKeyStringForServer
{
    SecKeyRef sPublicKeyRef = nil;
    NSData   *sPublicKeyData;
    NSString *sPublicKeyString;
    
    [[self class] secKeyRef:&sPublicKeyRef tag:kiOSPublicKeyTag];
    
    if (sPublicKeyRef == nil)
    {
        [[self class] removeAllRSAKeys];
        [[self class] generateKeyPairWithPublicKey:&sPublicKeyRef privateKey:nil];
    }
    
    sPublicKeyData = [[self class] dataFromKey:sPublicKeyRef];
    sPublicKeyString  = base64_encode_data(sPublicKeyData);
    
    return convertPublicKeyForServer(sPublicKeyString);
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
    NSData   *sEncryptData  = nil;
    size_t   sBufferLength  = SecKeyGetBlockSize(aKey);
    uint8_t  *sBuffer       = malloc(sBufferLength);
    
    OSStatus sResult = SecKeyEncrypt(aKey,
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
    NSData   *sDecryptData  = nil;
    size_t   sBufferLength  = SecKeyGetBlockSize(aKey);
    uint8_t  *sBuffer       = malloc(sBufferLength);
    
    OSStatus sResult = SecKeyDecrypt(aKey,
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
    
    NSData *publicKeyBits = base64_decode(aPublicKeyOniOS);
    
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
    NSString * ret = base64_encode_data(encKey);
    
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

NSString *base64_encode_data(NSData *data){
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

NSData *base64_decode(NSString *str){
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

@end
