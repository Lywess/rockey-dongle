#pragma once

#include <base/base.h>

#include <openssl/evp.h>

rLANG_DECLARE_MACHINE

/**
 *! ... 只支持签名, 用于X509证书的管理 ...
 */
rLANGEXPORT EVP_PKEY* rLANGAPI Rockey_RSA2048_New(uint32_t E, const uint8_t N[256], const uint8_t hid[12], int id);
rLANGEXPORT EVP_PKEY* rLANGAPI Rockey_P256_New(const uint8_t X[32], const uint8_t Y[32], const uint8_t hid[12], int id);
rLANGEXPORT EVP_PKEY* rLANGAPI Rockey_SM2_New(const uint8_t X[32], const uint8_t Y[32], const uint8_t hid[12], int id);
rLANGEXPORT void rLANGAPI Rockey_PKEY_Free(EVP_PKEY* pkey);

rLANG_DECLARE_END
