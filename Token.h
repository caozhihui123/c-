#include <string>
#include <cstdio>
#include <ctime>
#include <openssl/evp.h>
#include "linuxheader.h"

class Token{
public:
    Token(std::string username, std::string salt)
        : username_(username),
          salt_(salt)
    {
        std::string tokenGen = username_ + salt_;

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        EVP_DigestUpdate(ctx, tokenGen.c_str(), tokenGen.size());
        EVP_DigestFinal_ex(ctx, md, &md_len);
        EVP_MD_CTX_free(ctx);

        char frag[3] = {0};
        for(unsigned int i = 0; i < md_len; ++i){
            sprintf(frag, "%02x", md[i]);
            token = token + frag;
        }

        char timeStamp[20];
        time_t now = time(NULL);
        struct tm *ptm = localtime(&now);
        sprintf(timeStamp, "%02d%02d%02d%02d",
                ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);

        token = token + timeStamp;
    }

    std::string token;

private:
    std::string username_;
    std::string salt_;
};
