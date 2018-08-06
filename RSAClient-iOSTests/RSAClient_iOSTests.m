//
//  RSAClient_iOSTests.m
//  RSAClient-iOSTests
//
//  Created by tigi on 2018. 4. 27..
//  Copyright © 2018년 tigi. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "AFHTTPSessionManager.h"
#import "RSAManager.h"

static NSString       *const      kPlainText          = @"TEST PLAIN TEXT";
static NSTimeInterval  const      kTestBlockTimeout   = 2000;
static NSString       *const      kLocalHost          = @"http://localhost:8080";

static NSString * const kEmbededTestServerPublicKeyString = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhHOx/thUgKvWp5/cyE6HXbfYBqSVDArBA/NCmY6SsrdWcAc1aXUh2Ho/H3jpQSvkqfqGrfykcNP4Z/WjsLMp3Iyw+dXnOuIZbezuAuB0DIZLMLGlu42HPKQIrE+AaxF7ISLVQrc9LVjzjjNtj+SeYKxP+3+1DNk4jBTP1IraN//zaxND2Kz3iQUJszIXZNeVPG+mUqBqxsJBV0Ejp7BqaziCpnF/4CqSC11+D6Inm0ItwUa5lQZhViSr4689fhYt3Hy7LSsBAJ4Rcv+4HQRM9R4IIE1KBTYUhHTO7SSM8U06PyAwWfUJ9WVoPYqtHgP4BludRk6iTS2Yzwo9FeeWbQIDAQAB";
static NSString * const kEmbededTestServerPrivateKeyString = @"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCEc7H+2FSAq9ann9zIToddt9gGpJUMCsED80KZjpKyt1ZwBzVpdSHYej8feOlBK+Sp+oat/KRw0/hn9aOwsyncjLD51ec64hlt7O4C4HQMhkswsaW7jYc8pAisT4BrEXshItVCtz0tWPOOM22P5J5grE/7f7UM2TiMFM/Uito3//NrE0PYrPeJBQmzMhdk15U8b6ZSoGrGwkFXQSOnsGprOIKmcX/gKpILXX4PoiebQi3BRrmVBmFWJKvjrz1+Fi3cfLstKwEAnhFy/7gdBEz1HgggTUoFNhSEdM7tJIzxTTo/IDBZ9Qn1ZWg9iq0eA/gGW51GTqJNLZjPCj0V55ZtAgMBAAECggEADD/a7VO6dO/veS8qrwe8Mymme+7KrgNsmF3uAd+Sp56XCuNPyEIB8FBV+CYphFJ34lR+Eic0Wg7wgUTRb60SKQiF8YUbznFMosLvvCpf8SyWVZmIV1Eeebg96RmtKbnDJmxfRr1FliUM2VDeSBl/oDcvanYEG30XYrUmB2UUC2upWnAzYo1h3zDkZBKR2mAr7IiUTGnFZjdG+yG6x0dSoE+KGR47F9QqZ+ofUxCJmHH4NcKJ0G6tsf9TN8Dtum/Am3TMp5THq1ZwQ7K+T9LBP4z9SGA9MOpmAMwUKk4ve/3UBDro3ENQqePFgRB0Pn/3MqAGGN9rNH6ohyLC+/IyLQKBgQC6dMwq3yXaotd/D0yxvV2ZcIu2k+b7Nav0CvudXkKp375wWr+KwpLcveS7JxdMp4DZqiW6pwi/BXw1oBx1zIM85D37MxpXfNDrb8IwiB+giPycdTqyoEFx3Byy67FSOcLcvvYp0H2rp+zVKIiA1X1nN6+EfrXpB+Nfp/ss6HWEcwKBgQC12nZThqb77gtDN/B3ZWqYuGXSunSY1UWOnyc+hn/gPP427gqP9HFN/KZIdGVSGqyP87PUm/H4npW95R/qppJuvlIXAwBDdvTpGctyRSWBM2VYWbOeOvJmdhQRF5wfuEmdfNSeNCO94HsB9jgjoGmaigcAyxSaMAzk0D/B92qhnwKBgEpS/H+qa+B3QQd5Bc1j+seLQWYKFuzUPDMPnbThOhmVAsiuo+OgJAKx/1dLAdKggpBBbsC0jJv4h8aoiC+80iOXp81WVY3CR1VSO0o1OMY5VNjZMgi6MNw+LYJ0yT5JoA92X5HTdgTS72kYuzD/6PkYDXL3P3QgnNYok8sW7qFZAoGAEWjCnyhq3/9f8KVwTd3VoJ02kj/rXZ49NHQkC6ZQo6TzKUsMk89w8WhYeuM5t+x5zKYl9xqexZBZAX7n2UztA9EQhsdwxQSkWZRwl5XrCz1iXFzqByHZhtmS/jfmaFr6ISuMJ0ESkuDkpcFuimqW8YZ5OSg35rLm6RjOocEP4j0CgYBWByb6sgiOLQzc2JU+Is4Lm5NxDhpfqT0D+A52uCfTX4GuqPGrgHgcOEivAuc/161o3kpiqowpkh4O/uWgdiFej7nlJRRBr5DetzZvHKCe+datr6Ywmd5jwRlIX7FEHoyQE4GFPpQ1xdMUqoH39ntPUoc2+d9cyLLpTiESYgnCzA==";

@interface RSAClient_iOSTests : XCTestCase

@end

@implementation RSAClient_iOSTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    [self setContinueAfterFailure:false];
    NSLog(@"******** Original string: %@ ********", kPlainText);
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSendRequestForGeneratingKey
{
    NSString *description = [NSString stringWithFormat:@"%s", __FUNCTION__];
    XCTestExpectation *expectation = [self expectationWithDescription:description];
    
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager GET:[NSString stringWithFormat:@"%@/generateKey", kLocalHost] parameters:nil progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        NSString *sResultString = [NSString stringWithUTF8String:[responseObject bytes]];
        NSLog(@"%@", sResultString);
        XCTAssertNotNil(sResultString, @"sResultString must be not nil");
        [expectation fulfill];
    } failure:^(NSURLSessionTask *operation, NSError *error) {
        NSLog(@"Error: %@", error);
        [expectation fulfill];
        XCTFail(@"API ERROR : generateKey");
    }];
    
    [self waitForExpectationsWithTimeout:kTestBlockTimeout handler:^(NSError *aError) {
        XCTAssertNil(aError, @"Timeout Error : %@", aError);
    }];
}

- (void)testRSAByEmbededServerKeys
{
    NSString *sEncryptedString = [RSAManager encryptString:kPlainText publicKey:kEmbededTestServerPublicKeyString tag:nil];
    NSLog(@"Enctypted with public key : %@", sEncryptedString);
    XCTAssertNotNil(sEncryptedString, @"sEncryptedString must be not nil");

    NSString *sDecryptedString = [RSAManager decryptString:sEncryptedString privateKey:kEmbededTestServerPrivateKeyString tag:nil];
    NSLog(@"******** Decrypted with private key : %@ ********", sDecryptedString);
    XCTAssertNotNil(sDecryptedString, @"sDecryptedString must be not nil");
    XCTAssert([sDecryptedString isEqualToString:kPlainText], @"sDecryptedString must be equaled with sPlanText");
}

- (void)testEncryptionByServerPublicKey
{
    NSString *description = [NSString stringWithFormat:@"%s", __FUNCTION__];
    XCTestExpectation *expectation = [self expectationWithDescription:description];
    
    // get public key from server
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager GET:[NSString stringWithFormat:@"%@/getPublicKey", kLocalHost] parameters:nil progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        NSString *sPublicKeyString = [NSString stringWithUTF8String:[responseObject bytes]];
        NSLog(@"******** Public key from JAVA ********");
        NSLog(@"-----BEGIN PUBLIC KEY-----");
        NSLog(@"%@", sPublicKeyString);
        NSLog(@"-----END PUBLIC KEY-----");
        
        // encrypt on iOS
        NSString *sEncryptedString = [RSAManager encryptString:kPlainText publicKey:sPublicKeyString tag:nil];
        NSLog(@"Enctypted with public key : %@", sEncryptedString);
        XCTAssertNotNil(sEncryptedString, @"sEncryptedString must be not nil");
        
        
        // decrypt on server
        AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
        manager.responseSerializer = [AFHTTPResponseSerializer serializer];
        NSDictionary *sParamDic = @{
                                    @"encryptText" : sEncryptedString
                                    };
        [manager POST:[NSString stringWithFormat:@"%@/decryptByPrivateKey", kLocalHost] parameters:sParamDic progress:nil success:^(NSURLSessionTask *task, id responseObject) {
            NSString *sDecryptText = [NSString stringWithUTF8String:[responseObject bytes]];
            NSLog(@"******** Decrypted with private key from JAVA : %@ ********", sDecryptText);
            XCTAssert([sDecryptText isEqualToString:kPlainText], @"sDecryptText must be equaled with sPlanText");
            
            [expectation fulfill];
        } failure:^(NSURLSessionTask *operation, NSError *error) {
            NSLog(@"Error: %@", error);
            [expectation fulfill];
            XCTFail(@"API ERROR : decryptByPrivateKey");
        }];
        
    } failure:^(NSURLSessionTask *operation, NSError *error) {
        NSLog(@"Error: %@", error);
        [expectation fulfill];
        XCTFail(@"API ERROR : getPublicKey");
    }];
    
    [self waitForExpectationsWithTimeout:kTestBlockTimeout handler:^(NSError *aError) {
        XCTAssertNil(aError, @"Timeout Error : %@", aError);
    }];
}

- (void)testRSAByGeneratediOSKeys
{
//    [RSAManager removeAllRSAKeys];
    [RSAManager generateKeyPair];

    NSString *sEncryptedString = [RSAManager iOSKeyEncryptString:kPlainText];
    NSLog(@"Enctypted with public key : %@", sEncryptedString);
    XCTAssertNotNil(sEncryptedString, @"sEncryptedString must be not nil");

    NSString *sDecryptedString = [RSAManager iOSKeyDecryptString:sEncryptedString];
    NSLog(@"******** Decrypted with private key : %@ ********", sDecryptedString);
    XCTAssertNotNil(sDecryptedString, @"sDecryptedString must be not nil");
    XCTAssert([sDecryptedString isEqualToString:kPlainText], @"sDecryptedString must be equaled with sPlanText");
}

- (void)testDecryptionByiOSPrivateKey
{
    [RSAManager generateKeyPair];
    
    NSString *description = [NSString stringWithFormat:@"%s", __FUNCTION__];
    XCTestExpectation *expectation = [self expectationWithDescription:description];
    
    NSString *siOSPublicKeyString = [RSAManager iOSPublicKeyString];
    XCTAssertNotNil(siOSPublicKeyString, @"siOSPublicKeyString must be not nil");
    NSLog(@"-----BEGIN PUBLIC KEY for SERVER-----");
    NSLog(@"%@", siOSPublicKeyString);
    NSLog(@"-----END PUBLIC KEY for SERVER-----");
    
    // encrypt on server
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    NSDictionary *sParamDic = @{
                                @"plainText" : kPlainText,
                                @"publicKey" : siOSPublicKeyString
                                };
    [manager POST:[NSString stringWithFormat:@"%@/encryptWithPublicKeyParam", kLocalHost] parameters:sParamDic progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        NSString *sEncryptedString = [NSString stringWithUTF8String:[responseObject bytes]];
        NSLog(@"******** Enctypted with public key from java ********");
        NSLog(@"%@", sEncryptedString);
        XCTAssertNotNil(sEncryptedString, @"sEncryptText must be not nil");
        
        // decrypt on iOS
        NSString *sDecryptedString = [RSAManager iOSKeyDecryptString:sEncryptedString];
        NSLog(@"******** Decrypted with private key : %@ ********", sDecryptedString);
        XCTAssertNotNil(sDecryptedString, @"sDecryptedString must be not nil");
        XCTAssert([sDecryptedString isEqualToString:kPlainText], @"sDecryptedString must be equaled with sPlanText");
        
        [expectation fulfill];
    } failure:^(NSURLSessionTask *operation, NSError *error) {
        NSLog(@"Error: %@", error);
        [expectation fulfill];
        XCTFail(@"API ERROR : encryptWithPublicKeyParam");
    }];
    
    [self waitForExpectationsWithTimeout:kTestBlockTimeout handler:^(NSError *aError) {
        XCTAssertNil(aError, @"Timeout Error : %@", aError);
    }];
}

@end
