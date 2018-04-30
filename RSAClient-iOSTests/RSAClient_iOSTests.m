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

- (void)testSendRequestForGeneratingKey {
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

- (void)testRSAByEmbededServerKeys {
    NSString *sEncryptedString = [RSAManager serverKeyEncryptString:kPlainText];
    NSLog(@"Enctypted with public key : %@", sEncryptedString);
    XCTAssertNotNil(sEncryptedString, @"sEncryptedString must be not nil");

    NSString *sDecryptedString = [RSAManager serverKeyDecryptString:sEncryptedString];
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

- (void)testRSAByGeneratediOSKeys {
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
    
    NSString *siOSPublicKeyString = [RSAManager iOSPublicKeyStringForServer];
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
