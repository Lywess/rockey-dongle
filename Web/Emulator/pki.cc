#include <base/base.h>

#include <Interface/dongle.h>
#include <Interface/script.h>

#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sm4.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 *!
 */
#include "pki.h"

///
/// TODO: LiangLI, 应该是使用 Engine 接口完成, 略麻烦, 暂时还是直接访问结构内部成员 ...
///
#include "third_party/TASSL-1.1.1/crypto/engine/eng_local.h"
#include "third_party/TASSL-1.1.1/crypto/rsa/rsa_local.h"
#include "third_party/TASSL-1.1.1/crypto/ec/ec_local.h"
#include "third_party/TASSL-1.1.1/include/crypto/evp.h"

rLANG_DECLARE_MACHINE

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("j@PKI");

/**
 *!
 */
rLANGIMPORT int rLANGAPI
RockeySignRSA2048(const uint8_t hid[12], int id, int type, const uint8_t* dgst, int dlen, uint8_t sign[256])
    __attribute__((__import_module__("rLANG"), __import_name__("RockeySignRSA2048")));
rLANGIMPORT int rLANGAPI
RockeySignP256(const uint8_t hid[12], int id, int type, const uint8_t* dgst, int dlen, uint8_t sign[64])
    __attribute__((__import_module__("rLANG"), __import_name__("RockeySignP256")));
rLANGIMPORT int rLANGAPI
RockeySignSM2(const uint8_t hid[12], int id, int type, const uint8_t* dgst, int dlen, uint8_t sign[64])
    __attribute__((__import_module__("rLANG"), __import_name__("RockeySignSM2")));

/**
 *!
 */
struct Rockey_RSA final : RSA {
  rsa_meth_st override_;
  uint8_t hid_[12];
  int id_;
};

struct Rockey_EC_KEY final : EC_KEY {
  ec_key_method_st override_;
  uint8_t hid_[12];
  int id_;
};

/**
 *!
 */
rLANGWASMEXPORT EVP_PKEY* rLANGAPI Rockey_RSA2048_New(uint32_t E, const uint8_t N[256], const uint8_t hid[12], int id) {
  return nullptr;
}
rLANGWASMEXPORT EVP_PKEY* rLANGAPI Rockey_P256_New(const uint8_t X[32],
                                                   const uint8_t Y[32],
                                                   const uint8_t hid[12],
                                                   int id) {
  return nullptr;
}
rLANGWASMEXPORT EVP_PKEY* rLANGAPI Rockey_SM2_New(const uint8_t X[32],
                                                  const uint8_t Y[32],
                                                  const uint8_t hid[12],
                                                  int id) {
  return nullptr;
}

rLANGWASMEXPORT void rLANGAPI Rockey_PKEY_Free(EVP_PKEY* pkey) {
  return EVP_PKEY_free(pkey);
}

/**
 *!
 */
rLANGWASMEXPORT int Initialize() {
  rlLOGI(TAG, "\n\n%s%s%s\n\n",  //@ third_party/TASSL-1.1.1/LICENSE
         "This product includes software developed by the OpenSSL Project\n",
         "This product includes cryptographic software written by Eric Young (eay@cryptsoft.com)\n",
         "This product includes software developed by Beijing JN TASS Technology Co., Ltd. TaSSL "
         "Project.(http://www.tass.com.cn/)\n");
  for (int i = 0; i <= 6; ++i) {
    rlLOGW(TAG, "V[%d]: %s", i, OpenSSL_version(i));
  }

  SSL_library_init();
  SSL_load_error_strings();

  uint8_t buffer[128];
  FILE* fp = fopen("/dev/random", "rb");
  if (fp) {
    fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
  }
  RAND_seed(buffer, sizeof(buffer));
  return 0;
}

rLANGWASMEXPORT void RANDSeedBytes(const void* buff, size_t size) {
  RAND_seed(buff, size);
}

rLANG_DECLARE_END
