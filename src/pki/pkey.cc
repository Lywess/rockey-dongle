#include <base/base.h>

#include "pkey.h"

#ifdef _WIN32
#include <intrin.h>

int _InterlockedExchangeAdd(volatile int* v, int val) {
  static_assert(sizeof(long) == sizeof(int));
  return _InterlockedExchangeAdd((volatile long*)v, val);
}
#endif /* _WIN32 */

///
/// TODO: LiangLI, 应该是使用 Engine 接口完成, 略麻烦, 暂时还是直接访问结构内部成员 ...
///
#include "third_party/TASSL-1.1.1/crypto/ec/ec_local.h"
#include "third_party/TASSL-1.1.1/crypto/engine/eng_local.h"
#include "third_party/TASSL-1.1.1/crypto/rsa/rsa_local.h"
#include "third_party/TASSL-1.1.1/include/crypto/evp.h"

rLANG_DECLARE_MACHINE

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("pki$i");

/**
 *!
 */
static RSA_METHOD rockey_rsa_override_;
struct Rockey_RSA final : RSA {
  XIRockeyPKEY* pkey;
};

static EC_KEY_METHOD rockey_ec_key_override_;
struct Rockey_EC_KEY final : EC_KEY {
  XIRockeyPKEY* pkey;
};

static int rLANG_EVP_PKEY_Decrypt(EVP_PKEY_CTX* ctx,
                                  unsigned char* out,
                                  size_t* outlen,
                                  const unsigned char* in,
                                  size_t inlen) {
  EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  if (pkey) {
    switch (EVP_PKEY_id(pkey)) {
      case EVP_PKEY_RSA: {
        RSA* rsa = EVP_PKEY_get0_RSA(pkey);
        if (rsa && rsa->meth == &rockey_rsa_override_) {
          int result = static_cast<Rockey_RSA*>(rsa)->pkey->Decrypt(out, (int)*outlen, in, (int)inlen);
          if (result > 0) {
            *outlen = result;
            return 1;
          } else {
            rlLOGE(TAG, "Rockey.RSA[%p].Decrypt error %d", rsa, result);
            return -2;
          }
        }
      } break;

      case EVP_PKEY_EC:
      case EVP_PKEY_SM2: {
        EC_KEY* eckey = EVP_PKEY_get0_EC_KEY(pkey);
        if (eckey && eckey->meth == &rockey_ec_key_override_) {
          int result = static_cast<Rockey_EC_KEY*>(eckey)->pkey->Decrypt(out, (int)*outlen, in, (int)inlen);
          if (result > 0) {
            *outlen = result;
            return 1;
          } else {
            rlLOGE(TAG, "Rockey.EC_KEY[%p].Decrypt error %d", eckey, result);
            return -2;
          }
        }
      } break;
    }
  }
  return ctx->pmeth->decrypt(ctx, out, outlen, in, inlen);
}

rLANGEXPORT void rLANGAPI RockeyPKEY_Initialize(void) {
  rLANG_EVP_PKEY_CTX_HookDecrypt(rLANG_EVP_PKEY_Decrypt);
}

/**
 *!
 */
rLANGWASMEXPORT EVP_PKEY* rLANGAPI RockeyPKEY_RSA_New(uint32_t E, const uint8_t N[], int nlen, XIRockeyPKEY* pkey) {
  RSA_METHOD& override_ = rockey_rsa_override_;

  if (!override_.name) {
    override_ = *RSA_get_default_method();
    override_.name = OPENSSL_strdup("Rockey.RSA.Cipher");
    override_.rsa_sign = [](int type, const unsigned char* m, unsigned int m_length, unsigned char* sigret,
                            unsigned int* siglen, const RSA* rsa) {
      const auto* rockey = static_cast<const Rockey_RSA*>(rsa);
      int result = rockey->pkey->Sign(type, m, m_length, sigret, *siglen);
      if (result < 0) {
        rlLOGE(TAG, "Rockey.RSA.sign Error %d", result);
        return -2;
      }
      *sigret = result;
      return 1;
    };
    override_.rsa_priv_enc = [](int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
      int size = RSA_size(rsa);  // Checked to[size]
      const auto* rockey = static_cast<const Rockey_RSA*>(rsa);
      int result = rockey->pkey->Sign(padding, from, flen, to, size);
      if (result < 0) {
        rlLOGE(TAG, "Rockey.RSA.sign Error %d", result);
        return -2;
      }
      return size;
    };
  }

  Rockey_RSA* rsa = (Rockey_RSA*)OPENSSL_zalloc(sizeof(Rockey_RSA));
  if (!rsa)
    return nullptr;

  rsa->meth = &override_;
  rsa->flags = rsa->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
  rsa->references = 1;
  rsa->pkey = pkey;

  rsa->lock = CRYPTO_THREAD_lock_new();
  rsa->n = BN_bin2bn(N, nlen, nullptr);
  rsa->e = BN_new();

  if (!rsa->lock || !rsa->n || !rsa->e || 1 != BN_set_word(rsa->e, E) ||
      1 != CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, rsa, &rsa->ex_data) ||
      (rsa->meth->init && 1 != rsa->meth->init(rsa))) {
    RSA_free(rsa);
    return nullptr;
  }

  EVP_PKEY* evp_pkey = EVP_PKEY_new();
  if (!evp_pkey || 1 != EVP_PKEY_set1_RSA(evp_pkey, rsa)) {
    RSA_free(rsa);
    EVP_PKEY_free(evp_pkey);
    return nullptr;
  }

  RSA_free(rsa);
  return evp_pkey;
}

rLANGWASMEXPORT EVP_PKEY* rLANGAPI RockeyPKEY_EC_KEY_New(const uint8_t pubkey[],
                                                         int publen,
                                                         XIRockeyPKEY* pkey,
                                                         int nid) {
  EC_KEY_METHOD& override_ = rockey_ec_key_override_;

  if (!override_.name) {
    override_ = *EC_KEY_get_default_method();
    override_.name = OPENSSL_strdup("Rockey.EC_KEY.Cipher");
    override_.sign = [](int type, const unsigned char* dgst, int dlen, unsigned char* sig, unsigned int* siglen,
                        const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey) {
      const auto* rockey = static_cast<const Rockey_EC_KEY*>(eckey);
      int result = rockey->pkey->Sign(type, dgst, dlen, sig, *siglen);
      if (result < 0) {
        rlLOGE(TAG, "Rockey.EC_KEY.Sign Error %d", result);
        return -2;
      }
      *siglen = result;
      return 1;
    };
  }

  Rockey_EC_KEY* ret = (Rockey_EC_KEY*)OPENSSL_zalloc(sizeof(Rockey_EC_KEY));
  if (!ret)
    return nullptr;

  ret->version = 1;
  ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;
  ret->references = 1;

  ret->pkey = pkey;
  ret->meth = &override_;
  ret->lock = CRYPTO_THREAD_lock_new();
  ret->group = EC_GROUP_new_by_curve_name(nid);
  EC_POINT* point = ret->pub_key = EC_POINT_new(ret->group);

  if (!ret->lock || !ret->group || !CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EC_KEY, ret, &ret->ex_data) ||
      (ret->meth->init != NULL && ret->meth->init(ret) == 0) ||
      (ret->meth->set_group != NULL && ret->meth->set_group(ret, ret->group) == 0) || !point ||
      1 != EC_POINT_oct2point(ret->group, point, pubkey, publen, nullptr)) {
    char message[200];
    int error = ERR_get_error();
    ERR_error_string(error, message);
    EC_KEY_free(ret);

    rlLOGE(TAG, "Rockey.EC_KEY.Signer.New Error %d %s", error, message);
    return nullptr;
  }

  EVP_PKEY* evp_pkey = EVP_PKEY_new();
  if (!evp_pkey || 1 != EVP_PKEY_set1_EC_KEY(evp_pkey, ret)) {
    EC_KEY_free(ret);
    EVP_PKEY_free(evp_pkey);
    return nullptr;
  }

  if (nid == NID_sm2)
    EVP_PKEY_set_alias_type(evp_pkey, EVP_PKEY_SM2);
  EC_KEY_free(ret);
  return evp_pkey;
}

rLANG_DECLARE_END
