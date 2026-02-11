#pragma once

#include <ntctw_types.h>
#include <cstddef>
#include <string>

class SoftToken
{
public:
    SoftToken() = default;
    ~SoftToken() = default;

    int initialize() { return NTCTW_ERRORS::SUCCESS; }
    int finalize() { return NTCTW_ERRORS::SUCCESS; }

    int openSession(unsigned long /*slotId*/) { return NTCTW_ERRORS::SUCCESS; }
    int closeSession() { return NTCTW_ERRORS::SUCCESS; }

    // Минимальная заглушка для createPublicKey, используется Avpass'ом
    int createPublicKey(const std::string& /*id*/,
                        const std::string& /*label*/,
                        bool /*is_ephemeral*/,
                        unsigned long /*sec_level*/,
                        const unsigned char* /*value*/,
                        unsigned long /*size*/,
                        unsigned long* /*key_handle*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    int encrypt(unsigned long /*key_handle*/, const unsigned char* /*in*/, size_t /*in_len*/,
                const unsigned char* /*header*/, unsigned long /*header_len*/,
                unsigned char* /*out*/, size_t* /*out_len*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    int destroyKey(unsigned long /*key_handle*/)
    {
        return NTCTW_ERRORS::SUCCESS;
    }

    int cipherInit(void** /*cipher_ctx*/, NTCTW_CIPHER_ALG /*alg*/,
                   const unsigned char* /*key*/, unsigned long /*key_len*/,
                   const unsigned char* /*iv*/, unsigned long /*iv_len*/,
                   int /*enc_mode*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    int cipherControl(void* /*cipher_ctx*/, int /*param_type*/,
                      void* /*param*/, unsigned long /*param_len*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    int cipherDo(void* /*cipher_ctx*/, const unsigned char* /*in*/,
                 unsigned long /*in_len*/, unsigned char* /*out*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    int cipherCleanup(void* /*cipher_ctx*/)
    {
        return NTCTW_ERRORS::SUCCESS;
    }

    int randAddEntropy(const unsigned char* /*buf*/, unsigned long /*size*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    int randBytes(unsigned char* /*buf*/, unsigned long /*size*/)
    {
        return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
    }

    void randCleanup() {}
};

