//
//  SLEncrypt.h
//  SLEncrypt
//
//  Created by admin on 2022/3/23.
//  Copyright © 2022 SYC. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SLEncrypt : NSObject

/**
 加盐 md5摘要

 @param plaintext 明文
 @return  加盐md5摘要数据
 */
+ (NSString *)getSaltMD5WithStr:(NSString *)plaintext;

/**
 对称加密数据
 
 @param plaintext 明文
 @param ivKey 对称加密密钥
 @return 返回对称加密数据
 */
+ (NSString *)encryptWithStr:(NSString *)plaintext ivKey:(NSString *)ivKey;

/**
 对称数据解密

 @param ciphertext 密文
 @param ivKey 对称加密密钥
 @return 返回明文数据
 */
+ (NSString *)decryptWithStr:(NSString *)ciphertext ivKey:(NSString *)ivKey;

/**
 RSA公钥加密

 @param plaintext 明文
 @param publicKey 公钥
 @return 返回RSA公钥加密数据
 */
+ (NSString *)encryptWithStr:(NSString *)plaintext publicKey:(NSString *)publicKey;

/**
 RSA私钥加密

 @param plaintext 明文
 @param privateKey 私钥
 @return 返回RSA私钥加密数据
 */
+ (NSString *)encryptWithStr:(NSString *)plaintext privateKey:(NSString *)privateKey;

/**
 RSA公钥解密

 @param encyptText 加密内容
 @param publicKey 公钥
 @return 返回RSA公钥解密明文
 */
+ (NSString *)decryptWithStr:(NSString *)encyptText publicKey:(NSString *)publicKey;

#ifdef DEBUG
/**
 RSA私钥解密

 @param encyptText 加密内容
 @param privateKey 私钥
 @return 返回RSA私钥钥解密明文
 */
+ (NSString *)decryptWithStr:(NSString *)encyptText privateKey:(NSString *)privateKey;

#endif

// MARK: - AESCipher 加密

/// AEC 加密字符串
/// @param content 加密内容
/// @param key 密钥
NSString * aesEncryptString(NSString *content, NSString *key);
/// AEC 加密字符串 16进制表现形式
/// @param content 加密内容
/// @param key 密钥
NSString * aesEncryptHexStr(NSString *content, NSString *key);
/// AEC 解密字符串
/// @param content 加密内容
/// @param key 密钥
NSString * aesDecryptString(NSString *content, NSString *key);

/// 普通字符串转换为十六进制的
/// @param string 转化内容
NSString * hexStringFromString(NSString *string);

/// AEC 加密
/// @param data 加密内容
/// @param key 密钥
NSData * aesEncryptData(NSData *data, NSData *key);
/// AEC 解密
/// @param data 加密内容
/// @param key 密钥
NSData * aesDecryptData(NSData *data, NSData *key);

@end
