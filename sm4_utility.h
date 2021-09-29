#ifndef SM4_UTILITY_H
#define SM4_UTILITY_H
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/sm4.h"
#include "file_utility.h"
enum SM4_UTILITY_ERROR_CODE {
    SM4_PRIVKEY_INVALID  = -1,
    READ_FILE_FAILED     = -2,
    WRITE_FILE_FAILED    = -3,

    SM3_INIT_FAILED      = -1,
    SM3_UPDATE_FAILED    = -2,
    SM3_FINAL_FAILED     = -3,
    POINT_IS_EMPTY       = -4,

    
    PRIVKEY_HEX_INVALID  = -12,
};
enum SM4_ENCRYPT_MODE {
    ECB,
    CBC
};
enum SM4_PADDING_MODE {
    ZERO,
    PKCS7,
    PKCS5
};
static uint8_t sm4_privkey[SM4_BLOCK_SIZE] = { 0 };     // SM4_BLOCK_SIZE = 16
static uint8_t block[SM4_BLOCK_SIZE] = { 0 };           // 128bit的分组块
static SM4_KEY key;
// 检查privkey是否小于等于16字节 不足16字节 按照0填充
// 函数返回1 则满足要求 否则返回SM4_PRIVKEY_INVALID
int sm4_privkey_is_valid(const char *privkey);
// 使用sm4 ecb模式加密
// plain_file_path:明文文件绝对路径
// privkey_path:私钥文件路径
// ctext_file_path:密文文件绝对路径
// 加密文件成功返回加密的字节数 否则返回-1
int sm4_encrypt_ecb(const char *plain_file_path, 
                    const char *privkey_path,
                    const char *ctext_file_path);
// 使用sm4 ecb模式解密
// ctext_file_path:密文文件绝对路径
// privkey_path:私钥文件路径
// plain_file_path:明文文件绝对路径
// msg_len:明文字节数
// 解密文件成功返回加密的字节数 否则返回-1
int sm4_decrypt_ecb(const char *ctext_file_path,
                    const char *privkey_path,
                    const char *plain_file_path);

#endif