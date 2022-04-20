//
//  SLEncrypt.m
//  SLEncrypt
//
//  Created by admin on 2022/3/23.
//  Copyright © 2022 SYC. All rights reserved.
//

#import "SLEncrypt.h"
#import "encry_rsa.h"
#import "encry.h"
#import "GTMBase64.h"
//#import <CommonCrypto/CommonCryptor.h>

@implementation SLEncrypt

+ (NSString *)getSaltMD5WithStr:(NSString *)plaintext
{
    const char *data = [plaintext UTF8String];
    if (plaintext.length == 0) {
        return nil;
    }
    char buf[16];
    memset(buf, 0, sizeof(buf));
    char a[5]="|0000";
    char *t = (char *)malloc(sizeof(char) * plaintext.length * 8);
    if (t == NULL) {
        return nil;
    }
    memset(t, 0, sizeof(char) * plaintext.length * 8);
    /**
     * 然后把data复制进去
     */
    strncat(t, data, strlen(data));
    
    /**
     * 再把a添加到后面
     */
    strncat(t, a , 5);
    
    get_md5(t, buf);
    NSString *str = [[NSString alloc] initWithData:[GTMBase64 encodeBytes:buf length:16] encoding:NSUTF8StringEncoding];
    free(t);
    return str;
}

+ (NSString *)decryptWithStr:(NSString *)ciphertext ivKey:(NSString *)ivKey
{
    if(ciphertext.length == 0 || ivKey.length == 0) {
        return nil;
    }
    NSData *data = [GTMBase64 decodeString:ciphertext];
    int ciphertext_len = (int)data.length;
    const char *ivkey_ = (const char *)[ivKey UTF8String];
    unsigned char *plaintext =(unsigned char *)malloc(sizeof(unsigned char) * ciphertext.length * 8);
    if (plaintext == NULL) {
        return nil;
    }
    int result = decrypt_AES_ECB((unsigned char *)data.bytes, ciphertext_len, ivkey_, plaintext);
    NSString *resultStr = nil;
    if(result > 0) {
       resultStr = [[NSString alloc] initWithBytes:plaintext length:result encoding:NSUTF8StringEncoding];
    }
    free(plaintext);
    return resultStr;
}

+ (NSString *)encryptWithStr:(NSString *)plaintext ivKey:(NSString *)ivKey
{
    if(plaintext.length == 0 || ivKey.length == 0) {
        return nil;
    }
    NSData *data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    int in_plain_len = (int)data.length;
    const char *ivkey_ = (const char *)[ivKey UTF8String];
    unsigned char *cipherText =(unsigned char *)malloc(sizeof(unsigned char) * plaintext.length * 8);
    if (cipherText == NULL) {
        return nil;
    }
    int result = encrypt_AES_ECB((unsigned char *)data.bytes, in_plain_len, ivkey_, cipherText);
    NSString *resultStr = nil;
    if(result > 0) {
        resultStr= [[NSString alloc] initWithData:[GTMBase64 encodeBytes:cipherText length:result] encoding:NSUTF8StringEncoding];;
    }
    free(cipherText);
    return resultStr;
}


+ (NSString *)decrypt128WithStr:(NSString *)ciphertext ivKey:(NSString *)ivKey
{
    if(ciphertext.length == 0 || ivKey.length == 0) {
        return nil;
    }
    NSData *data = [GTMBase64 decodeString:ciphertext];
    int ciphertext_len = (int)data.length;
    const char *ivkey_ = (const char *)[ivKey UTF8String];
    unsigned char *plaintext =(unsigned char *)malloc(sizeof(unsigned char) * ciphertext.length * 8);
    if (plaintext == NULL) {
        return nil;
    }
    int result = decrypt_AES_128_ECB((unsigned char *)data.bytes, ciphertext_len, ivkey_, plaintext);
    NSString *resultStr = nil;
    if(result > 0) {
       resultStr = [[NSString alloc] initWithBytes:plaintext length:result encoding:NSUTF8StringEncoding];
    }
    free(plaintext);
    return resultStr;
}

+ (NSString *)encrypt128WithStr:(NSString *)plaintext ivKey:(NSString *)ivKey
{
    if(plaintext.length == 0 || ivKey.length == 0) {
        return nil;
    }
    NSData *data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    int in_plain_len = (int)data.length;
    const char *ivkey_ = (const char *)[ivKey UTF8String];
    unsigned char *cipherText =(unsigned char *)malloc(sizeof(unsigned char) * plaintext.length * 8);
    if (cipherText == NULL) {
        return nil;
    }
    int result = encrypt_AES_128_ECB((unsigned char *)data.bytes, in_plain_len, ivkey_, cipherText);
    NSString *resultStr = nil;
    if(result > 0) {
        resultStr= [[NSString alloc] initWithData:[GTMBase64 encodeBytes:cipherText length:result] encoding:NSUTF8StringEncoding];;
    }
    free(cipherText);
    return resultStr;
}

+ (NSString *)encryptWithStr:(NSString *)plaintext publicKey:(NSString *)publicKey
{
    if(plaintext.length == 0 || publicKey.length == 0) {
        return nil;
    }
    const char *ivkey_ = (const char *)[publicKey UTF8String];
    char _key[1024] = {0};
    memcpy(_key, ivkey_, strlen(ivkey_));
    char *cipherText =(char *)malloc(sizeof(char) * 10000);
    if (cipherText == NULL) {
        return nil;
    }
    encryptByPublicKey(_key, (char *)[plaintext UTF8String], cipherText);
    NSString *str = [[NSString alloc] initWithUTF8String:cipherText];
    free(cipherText);
    return str;
}

+ (NSString *)encryptWithStr:(NSString *)plaintext privateKey:(NSString *)privateKey
{
    if(plaintext.length == 0 || privateKey.length == 0) {
        return nil;
    }
    const char *ivkey_ = (const char *)[privateKey UTF8String];
    char _key[1024] = {0};
    memcpy(_key, ivkey_, strlen(ivkey_));
    char *cipherText =(char *)malloc(sizeof(char) * 10000);
    if (cipherText == NULL) {
        return nil;
    }
    encryptByPrivateKey(_key, (char *)[plaintext UTF8String], cipherText);
    NSString *str = [[NSString alloc] initWithUTF8String:cipherText];
    free(cipherText);
    return str;
}

+ (NSString *)decryptWithStr:(NSString *)encyptText publicKey:(NSString *)publicKey
{
    if(encyptText.length == 0 || publicKey.length == 0) {
        return nil;
    }
    const char *ivkey_ = (const char *)[publicKey UTF8String];
    char _key[1024] = {0};
    memcpy(_key, ivkey_, strlen(ivkey_));
    char *outText =(char *)malloc(sizeof(char) * 10000);
    if (outText == NULL) {
        return nil;
    }
    decryptByPublicKey(_key, (char *)[encyptText UTF8String], outText);
    NSString *str = [[NSString alloc] initWithUTF8String:outText];
    free(outText);
    return str;
}
#ifdef DEBUG
+ (NSString *)decryptWithStr:(NSString *)encyptText privateKey:(NSString *)privateKey
{
    if(encyptText.length == 0 || privateKey.length == 0) {
        return nil;
    }
    const char *ivkey_ = (const char *)[privateKey UTF8String];
    char _key[1024] = {0};
    memcpy(_key, ivkey_, strlen(ivkey_));
    char *outText =(char *)malloc(sizeof(char) * 10000);
    if (outText == NULL) {
        return nil;
    }
    decryptByPrivateKey(_key, (char *)[encyptText UTF8String], outText);

    NSString *str = [[NSString alloc] initWithUTF8String:outText];
    free(outText);
    return str;
}
#endif


//NSString const *kInitVector = @"A-16-Byte-String";
//size_t const kKeySize = kCCKeySizeAES128;
//
//NSData * cipherOperation(NSData *contentData, NSData *keyData, CCOperation operation) {
//    NSUInteger dataLength = contentData.length;
//
//    void const *initVectorBytes = [kInitVector dataUsingEncoding:NSUTF8StringEncoding].bytes;
//    void const *contentBytes = contentData.bytes;
//    void const *keyBytes = keyData.bytes;
//
//    size_t operationSize = dataLength + kCCBlockSizeAES128;
//    void *operationBytes = malloc(operationSize);
//    size_t actualOutSize = 0;
//
//    CCCryptorStatus cryptStatus = CCCrypt(operation,
//                                          kCCAlgorithmAES,
//                                          kCCOptionPKCS7Padding,
//                                          keyBytes,
//                                          kKeySize,
//                                          initVectorBytes,
//                                          contentBytes,
//                                          dataLength,
//                                          operationBytes,
//                                          operationSize,
//                                          &actualOutSize);
//
//    if (cryptStatus == kCCSuccess) {
//        return [NSData dataWithBytesNoCopy:operationBytes length:actualOutSize];
//    }
//    free(operationBytes);
//    return nil;
//}
//
//NSString * aesEncryptString(NSString *content, NSString *key) {
//    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
//    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
//    NSData *encrptedData = aesEncryptData(contentData, keyData);
//    return [encrptedData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
//}
//
//NSString * aesEncryptHexStr(NSString *content, NSString *key){
//   NSString *str=aesDecryptString(content,key);
//   return hexStringFromString(str);
//}
//
////普通字符串转换为十六进制的。
//NSString * hexStringFromString(NSString *string){
//    NSData *myD = [string dataUsingEncoding:NSUTF8StringEncoding];
//    Byte *bytes = (Byte *)[myD bytes];
//    //下面是Byte 转换为16进制。
//    NSString *hexStr=@"";
//    for(int i=0;i<[myD length];i++)
//    {
//        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
//        if([newHexStr length]==1)
//            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
//        else
//            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
//    }
//    return hexStr;
//}
//
//NSString * aesDecryptString(NSString *content, NSString *key) {
//    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
//    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
//    NSData *decryptedData = aesDecryptData(contentData, keyData);
//    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
//}
//
//NSData * aesEncryptData(NSData *contentData, NSData *keyData) {
//    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kKeySize * 8, kKeySize];
//    NSCAssert(keyData.length == kKeySize, hint);
//    return cipherOperation(contentData, keyData, kCCEncrypt);
//}
//
//NSData * aesDecryptData(NSData *contentData, NSData *keyData) {
//    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kKeySize * 8, kKeySize];
//    NSCAssert(keyData.length == kKeySize, hint);
//    return cipherOperation(contentData, keyData, kCCDecrypt);
//}

@end
