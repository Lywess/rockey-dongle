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

rLANG_DECLARE_END
