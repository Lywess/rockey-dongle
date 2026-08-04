#pragma once

#include <base/base.h>

/**
 *!
 */
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 *!
 */
rLANG_DECLARE_MACHINE

/**
 *!
 */
XII_DECLARE_INTERFACE_BEGIN0(XIRockeyPKEY)
  /**
   *! RSA/P256.ECDSA/SM2.ECDSA ...
   */
  XIIMETHOD(Sign)(XIITHIZ int type, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen) XIIPURE;

  /**
   *! 只应该用于 GMTLS SM2ECIES 加密证书, RSA/ECC 应该使用 TLS_ECDHE_(RSA|ECDSA)_... 密码学套件 ...
   */
  XIIMETHOD(Decrypt)(XIITHIZ uint8_t* out, int outlen, const uint8_t* in, int inlen) XIIPURE;
XII_DECLARE_INTERFACE_END(XIRockeyPKEY)

/**
 *!
 */
rLANGEXPORT void rLANGAPI RockeyPKEY_Initialize(void);
rLANGEXPORT EVP_PKEY* rLANGAPI RockeyPKEY_RSA_New(uint32_t E, const uint8_t N[], int nlen, XIRockeyPKEY* pkey);
rLANGEXPORT EVP_PKEY* rLANGAPI RockeyPKEY_EC_KEY_New(const uint8_t pubkey[], int publen, XIRockeyPKEY* pkey, int nid);

rLANG_DECLARE_END
