#include "sm4_utility.h"
int sm4_privkey_is_valid(const char *privkey) {
    int len = strlen(privkey);
    if (len <= 0 || len > SM4_BLOCK_SIZE) {
        return SM4_PRIVKEY_INVALID;
    }
    int i = 0;
    for (;i < len;i++) {
        sm4_privkey[i] = privkey[i];
    }
    if (SM4_set_key(sm4_privkey, &key)) {
        return 1;
    }
    return SM4_PRIVKEY_INVALID;
}
int sm4_encrypt_ecb(const char *plain_file_path, 
                    const char *privkey_path,
                    const char *ctext_file_path) {
    char *privkey_buf = NULL;
    // 读私钥
    int key_len = read_file_content(privkey_path, &privkey_buf);
    if (key_len <= 0 || !privkey_buf) {
        return READ_FILE_FAILED;
    }
    // 检查私钥
    if (sm4_privkey_is_valid(privkey_buf) != 1) {
        free(privkey_buf);
        return SM4_PRIVKEY_INVALID;
    }
    char *message = NULL;
    int succ = 0;
    // 读明文
    int msg_len = read_file_content(plain_file_path, &message);
    if (msg_len <= 0) {
        succ = READ_FILE_FAILED;
        goto DONE;
    }
    int block_num = msg_len / SM4_BLOCK_SIZE;
    if (msg_len % SM4_BLOCK_SIZE) {     // 加上余数
        ++block_num;
    }
    int ctext_len = block_num * SM4_BLOCK_SIZE + 4; // 前4个字节存放明文字节数
    char *ctext = (char *)malloc(ctext_len);
    if (!ctext) {
        goto DONE;        
    }
    memcpy(ctext, &msg_len, sizeof(msg_len));   // 先拷贝明文字节数
    int i = 0;
    int start = 0;
    for (;i < block_num;i++) {
        memset(block, 0, sizeof(block));
        memcpy(block, message + start, SM4_BLOCK_SIZE);
        SM4_encrypt(block, block, &key);
        memcpy(ctext + start + 4, block, SM4_BLOCK_SIZE);
        start += SM4_BLOCK_SIZE;
    }
    succ = ctext_len;
    if (write_file_content(ctext_file_path, ctext, ctext_len) <= 0) {
        succ = WRITE_FILE_FAILED;
    }
DONE:
    if (privkey_buf) {
        free(privkey_buf);
    }
    if (message) {
        free(message);
    }
    if (ctext) {
        free(ctext);
    }
    return succ;
}
int sm4_decrypt_ecb(const char *ctext_file_path, 
                    const char *privkey_path,
                    const char *plain_file_path) {
    char *privkey_buf = NULL;
    // 读私钥
    int key_len = read_file_content(privkey_path, &privkey_buf);
    if (key_len <= 0 || !privkey_buf) {
        return READ_FILE_FAILED;
    }
    // 检查私钥
    if (sm4_privkey_is_valid(privkey_buf) != 1) {
        free(privkey_buf);
        return SM4_PRIVKEY_INVALID;
    }
    char *ctext = NULL;
    int succ = 0;
    // 读密文
    int ctext_len = read_file_content(ctext_file_path, &ctext);
    if (ctext_len <= 0) {
        succ = READ_FILE_FAILED;
        goto DONE;
    }
    ctext_len -= 4;     // 减去头4个字节
    if (ctext_len <= 0) {
        succ = READ_FILE_FAILED;
        goto DONE;
    }
    int msg_len = 0;
    memcpy(&msg_len, ctext, sizeof(msg_len));
    int block_num = ctext_len / SM4_BLOCK_SIZE;
    if (ctext_len % SM4_BLOCK_SIZE) {     // 加上余数
        ++block_num;
    }
    char *message = (char *)malloc(block_num * SM4_BLOCK_SIZE);
    if (!message) {
        goto DONE;        
    }
    int i = 0;
    int start = 0;
    for (;i < block_num;i++) {
        memset(block, 0, sizeof(block));
        memcpy(block, ctext + start + 4, SM4_BLOCK_SIZE);
        SM4_decrypt(block, block, &key);
        memcpy(message + start, block, SM4_BLOCK_SIZE);
        start += SM4_BLOCK_SIZE;
    }
    succ = msg_len;
    if (write_file_content(plain_file_path, message, msg_len) <= 0) {
        succ = WRITE_FILE_FAILED;
    }
DONE:
    if (privkey_buf) {
        free(privkey_buf);
    }
    if (ctext) {
        free(ctext);
    }
    if (message) {
        free(message);
    }
    return succ;
}