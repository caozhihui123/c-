#ifndef __FILEUTIL__
#define __FILEUTIL__
#include "linuxheader.h"
// 替换旧的 sha.h 为 EVP 接口头文件（OpenSSL 3.0 推荐）
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <stdexcept>  // 用于异常处理

class FileUtil{
public:
    static std::string sha1File(const char *path){
        // 1. 打开文件（保留你原有的 open 系统调用方式）
        int fd = open(path, O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open file: " + std::string(path));
        }

        // 2. 初始化 EVP 哈希上下文（替代原 SHA_CTX）
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            close(fd);
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }

        // 3. 选择 SHA1 算法并初始化（替代 SHA1_Init）
        const EVP_MD* md = EVP_sha1();
        if (!md || EVP_DigestInit_ex(md_ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(md_ctx);
            close(fd);
            throw std::runtime_error("EVP_DigestInit_ex failed: " + 
                std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // 4. 循环读取文件并更新哈希（替代 SHA1_Update）
        char buf[4096] = {0};
        while(1){
            bzero(buf, sizeof(buf));
            ssize_t ret = read(fd, buf, sizeof(buf));
            if (ret == -1) {  // 处理 read 错误
                EVP_MD_CTX_free(md_ctx);
                close(fd);
                throw std::runtime_error("Read file error: " + std::string(path));
            }
            if (ret == 0) {   // 读取完毕
                break;
            }
            // 更新哈希值
            if (EVP_DigestUpdate(md_ctx, buf, ret) != 1) {
                EVP_MD_CTX_free(md_ctx);
                close(fd);
                throw std::runtime_error("EVP_DigestUpdate failed: " + 
                    std::string(ERR_error_string(ERR_get_error(), nullptr)));
            }
        }

        // 5. 完成哈希计算（替代 SHA1_Final）
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        if (EVP_DigestFinal_ex(md_ctx, md_value, &md_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            close(fd);
            throw std::runtime_error("EVP_DigestFinal_ex failed: " + 
                std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // 6. 释放资源
        EVP_MD_CTX_free(md_ctx);
        close(fd);

        // 7. 二进制哈希值转十六进制字符串（保留你原有的逻辑）
        std::string sha1Res;
        char frag[3]; // {'1' 'a' '\0'}
        for(int i = 0; i < md_len; ++i){
            sprintf(frag, "%02x", md_value[i]);
            sha1Res.append(frag);
        }

        return sha1Res;
    }
};
#endif