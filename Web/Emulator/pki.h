#pragma once

#include <base/base.h>
#include <openssl/evp.h>

rLANG_DECLARE_MACHINE

typedef uint16_t XIdRockeyPKEY;

/**
 *!
 */
rLANGEXPORT int rLANGAPI RockeyPKEY_Clear(XIdRockeyPKEY pkey);
rLANGEXPORT int rLANGAPI RockeyPKEY_CreateRSA(XIdRockeyPKEY pkey, uint32_t E, const uint8_t N[], int nlen);
rLANGEXPORT int rLANGAPI RockeyPKEY_CreateP256(XIdRockeyPKEY pkey, const uint8_t X[32], const uint8_t Y[32]);
rLANGEXPORT int rLANGAPI RockeyPKEY_CreateSM2(XIdRockeyPKEY pkey, const uint8_t X[32], const uint8_t Y[32]);
rLANGEXPORT EVP_PKEY* rLANGAPI EVP_PKEY_From_RockeyPKEY(XIdRockeyPKEY pkey);

/**
 *! For Tests ...
 */
rLANGEXPORT int rLANGAPI
RockeyPKEY_SignEx(XIdRockeyPKEY pkey, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen);
rLANGEXPORT int rLANGAPI
RockeyPKEY_DecryptEx(XIdRockeyPKEY pkey, uint8_t* out, int outlen, const uint8_t* in, int inlen);

/**
 *!
 */
rLANGEXPORT int rLANGAPI RockeyPKEY_VerifyX509(XIdRockeyPKEY pkey, const uint8_t* x509_der, int x509_size);
rLANGEXPORT int rLANGAPI RockeyPKEY_VerifyX509Req(const uint8_t* x509_req_der, int x509_req_size);

/**
 *! 签署CA根证书 ...
 */
rLANGEXPORT int rLANGAPI RockeyPKEY_SignRootCA(const char* subject,
                                               const char* comment,
                                               double notBefore,
                                               double notAfter,
                                               XIdRockeyPKEY pkey,
                                               const char* md,
                                               const uint8_t* v3_ext_der_if,
                                               int v3_ext_siz,
                                               uint8_t* out_x509_der,
                                               int siz_x509_der);

/**
 *! 创建CSR请求, 不验证 X509||X509_REQ 签名, 如需要验证, 手工调用 RockeyPKEY_VerifyX509 ...
 */
rLANGEXPORT int rLANGAPI RockeyPKEY_X509ReqFrom(const uint8_t* x509_or_req_der,
                                                int x509_or_req_size,
                                                XIdRockeyPKEY pkey,
                                                const char* md,
                                                uint8_t* out_x509_req_der,
                                                int siz_x509_req_der);

/**
 *! 签署CSR请求, 不验证 X509_REQ 签名, 如需要验证, 手工调用 RockeyPKEY_VerifyX509Req ...
 */
rLANGEXPORT int rLANGAPI RockeyPKEY_SignX509(const uint8_t* x509_req_der,
                                             int x509_req_siz,
                                             double notBefore,
                                             double notAfter,
                                             const uint8_t* x509_ca_if,
                                             int x509_ca_siz,
                                             XIdRockeyPKEY pkey,
                                             const char* md,
                                             const uint8_t* searia_number_if /* null for RandBytes(16) */,
                                             int searia_number_size,
                                             const uint8_t* v3_ext_der_if,
                                             int v3_ext_siz,
                                             uint8_t* out_x509_der,
                                             int siz_x509_der);

rLANG_DECLARE_END
