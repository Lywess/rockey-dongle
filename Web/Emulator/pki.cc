#include <base/base.h>

#include <Interface/dongle.h>
#include <Interface/script.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sm4.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <new>

/**
 *!
 */
#include "pki.h"

/**
 *!
 */
#include "src/pki/pkey.h"

rLANG_DECLARE_MACHINE

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("j@PKI");

/**
 *!
 */
constexpr size_t kCountRockeyPKEY = std::numeric_limits<XIdRockeyPKEY>::max() + 1;

/**
 *!
 */
rLANGIMPORT int rLANGAPI RockeyPKEY_Sign(XIdRockeyPKEY pkey, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen)
    __attribute__((__import_module__("rLANG"), __import_name__("RockeyPKEY_Sign")));
rLANGIMPORT int rLANGAPI RockeyPKEY_Decrypt(XIdRockeyPKEY pkey, uint8_t* out, int outlen, const uint8_t* in, int inlen)
    __attribute__((__import_module__("rLANG"), __import_name__("RockeyPKEY_Decrypt")));

static int SM2CipherFromASN1(uint8_t* cipher, const uint8_t* in, int inlen) {
  int result = -EFAULT;

  SM2_Ciphertext* asn1_cipher = d2i_SM2_Ciphertext(nullptr, &in, inlen);
  if (!asn1_cipher)
    return -EFAULT;

  do {
    const BIGNUM* C1x = SM2_Ciphertext_get0_C1x(asn1_cipher);
    const BIGNUM* C1y = SM2_Ciphertext_get0_C1y(asn1_cipher);
    const ASN1_OCTET_STRING* C3 = SM2_Ciphertext_get0_C3(asn1_cipher);
    const ASN1_OCTET_STRING* C2 = SM2_Ciphertext_get0_C2(asn1_cipher);
    if (!C1x || !C1y || !C3 || !C2)
      break;

    if (ASN1_STRING_length(C3) != 32)
      break;

    if (32 != BN_bn2binpad(C1x, &cipher[0], 32))
      break;

    if (32 != BN_bn2binpad(C1y, &cipher[32], 32))
      break;

    result = 96 + ASN1_STRING_length(C2);
    memcpy(&cipher[64], C3->data, 32);
    memcpy(&cipher[96], C2->data, result - 96);
  } while (0);

  SM2_Ciphertext_free(asn1_cipher);
  return result;
}

struct EmuXIRockeyPKEY final : XIRockeyPKEY {
  EmuXIRockeyPKEY(XIdRockeyPKEY index, int nid) : index_(index), nid_(nid) {}

  EmuXIRockeyPKEY(const EmuXIRockeyPKEY&) = delete;
  EmuXIRockeyPKEY& operator=(const EmuXIRockeyPKEY&) = delete;
  static constexpr int kSizeLimit = 4096;

  XIIMETHOD(Sign)(XIITHIZ int type, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen) override {
    dongle::Dongle::SecretBuffer<kSizeLimit> dummy;
    if (!sign) {
      sign = &dummy[0];
      signlen = kSizeLimit;
    }

    if (nid_ == NID_rsa) {
      return RockeyPKEY_Sign(index_, dgst, dlen, sign, signlen);
    } else if (nid_ == NID_X9_62_prime256v1 || nid_ == NID_sm2) {
      uint8_t RS[64];
      int result = RockeyPKEY_Sign(index_, dgst, dlen, RS, 64);
      if (64 != result) {
        rlLOGE(TAG, "RockeyPKEY_Sign NID %d => %d != 64", nid_, result);
        return -EFAULT;
      }

      BIGNUM* r = BN_bin2bn(&RS[0], 32, nullptr);
      BIGNUM* s = BN_bin2bn(&RS[32], 32, nullptr);
      ECDSA_SIG* sig = ECDSA_SIG_new();

      if (!r || !s || !sig) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return -ENOMEM;
      }

      ECDSA_SIG_set0(sig, r, s);
      result = i2d_ECDSA_SIG(sig, &sign);
      ECDSA_SIG_free(sig);
      return result;
    }

    return -EBADF;
  }

  XIIMETHOD(Decrypt)(XIITHIZ uint8_t* out, int outlen, const uint8_t* in, int inlen) override {
    dongle::Dongle::SecretBuffer<kSizeLimit> dummy;
    if(!out) {
      out = &dummy[0];
      outlen = kSizeLimit;
    }

    if (nid_ == NID_rsa)
      return RockeyPKEY_Decrypt(index_, out, outlen, in, inlen);

    if (nid_ != NID_sm2)
      return -EBADF;

    constexpr int kCipherSizeLimit = 800;
    if (inlen < 32 || inlen > kCipherSizeLimit) {
      rlLOGE(TAG, "SM2.decrypt invalid cipher size %d", inlen);
      return -EINVAL;
    }

    uint8_t cipher[kCipherSizeLimit + 96];
    inlen = SM2CipherFromASN1(cipher, in, inlen);
    if (inlen < 0)
      return inlen;
    if (!out)
      return inlen - 96;
    if (outlen < inlen - 96)
      return -E2BIG;

    return RockeyPKEY_Decrypt(index_, out, outlen, cipher, inlen);
  }

 protected:
  const XIdRockeyPKEY index_;
  const int nid_;
};

/**
 *!
 */
rLANG_DECLARE_PRIVATE_CONTEXT(STORAGE_EmuXIRockeyPKEY, sizeof(EmuXIRockeyPKEY));
static EVP_PKEY* all_rockey_pkey_[kCountRockeyPKEY];
static STORAGE_EmuXIRockeyPKEY all_rockey_memory_callback_[kCountRockeyPKEY];

/**
 *!
 */
rLANGWASMEXPORT int rLANGAPI RockeyPKEY_Clear(XIdRockeyPKEY pkey) {
  if (!all_rockey_pkey_[pkey])
    return -ENOENT;

  EVP_PKEY_free(all_rockey_pkey_[pkey]);
  all_rockey_pkey_[pkey] = nullptr;
  return 0;
}

rLANGWASMEXPORT int rLANGAPI RockeyPKEY_CreateRSA(XIdRockeyPKEY pkey, uint32_t E, const uint8_t N[], int nlen) {
  if (nlen < 256 || nlen > EmuXIRockeyPKEY::kSizeLimit)
    return -ERANGE;
  if (all_rockey_pkey_[pkey])
    return -EALREADY;

  XIRockeyPKEY* rockey = new (&all_rockey_memory_callback_[pkey]) EmuXIRockeyPKEY(pkey, NID_rsa);
  all_rockey_pkey_[pkey] = RockeyPKEY_RSA_New(E, N, nlen, rockey);

  return all_rockey_pkey_[pkey] ? 0 : -EFAULT;
}

rLANGWASMEXPORT int rLANGAPI RockeyPKEY_CreateP256(XIdRockeyPKEY pkey, const uint8_t X[32], const uint8_t Y[32]) {
  if (all_rockey_pkey_[pkey])
    return -EALREADY;

  uint8_t pubkey[65];
  pubkey[0] = 4;
  memcpy(&pubkey[1], X, 32);
  memcpy(&pubkey[33], Y, 32);

  XIRockeyPKEY* rockey = new (&all_rockey_memory_callback_[pkey]) EmuXIRockeyPKEY(pkey, NID_X9_62_prime256v1);
  all_rockey_pkey_[pkey] = RockeyPKEY_EC_KEY_New(pubkey, 65, rockey, NID_X9_62_prime256v1);

  return all_rockey_pkey_[pkey] ? 0 : -EFAULT;
}

rLANGWASMEXPORT int rLANGAPI RockeyPKEY_CreateSM2(XIdRockeyPKEY pkey, const uint8_t X[32], const uint8_t Y[32]) {
  if (all_rockey_pkey_[pkey])
    return -EALREADY;

  uint8_t pubkey[65];
  pubkey[0] = 4;
  memcpy(&pubkey[1], X, 32);
  memcpy(&pubkey[33], Y, 32);

  XIRockeyPKEY* rockey = new (&all_rockey_memory_callback_[pkey]) EmuXIRockeyPKEY(pkey, NID_sm2);
  all_rockey_pkey_[pkey] = RockeyPKEY_EC_KEY_New(pubkey, 65, rockey, NID_sm2);

  return all_rockey_pkey_[pkey] ? 0 : -EFAULT;
}

rLANGEXPORT EVP_PKEY* rLANGAPI EVP_PKEY_From_RockeyPKEY(XIdRockeyPKEY pkey) {
  return all_rockey_pkey_[pkey];
}

rLANGWASMEXPORT int rLANGAPI
RockeyPKEY_SignEx(XIdRockeyPKEY pkey, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen) {
  if (!dgst || !sign || signlen <= 0 || dlen <= 0)
    return -EINVAL;
  EVP_PKEY* rockey = EVP_PKEY_From_RockeyPKEY(pkey);
  if (!rockey)
    return -ENOENT;

  size_t slen = signlen;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rockey, nullptr);
  int result = EVP_PKEY_sign_init(ctx);
  if (result > 0)
    result = EVP_PKEY_sign(ctx, sign, &slen, dgst, dlen);
  EVP_PKEY_CTX_free(ctx);

  if (result <= 0)
    return -EFAULT;
  return (int)slen;
}

rLANGWASMEXPORT int rLANGAPI
RockeyPKEY_DecryptEx(XIdRockeyPKEY pkey, uint8_t* out, int outlen, const uint8_t* in, int inlen) {
  if (!out || !in || outlen <= 0 || inlen <= 0)
    return -EINVAL;

  if(inlen > EmuXIRockeyPKEY::kSizeLimit)
    return -ERANGE;

  EVP_PKEY* rockey = EVP_PKEY_From_RockeyPKEY(pkey);
  if (!rockey)
    return -ENOENT;

  size_t olen = outlen;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rockey, nullptr);
  int result = EVP_PKEY_decrypt_init(ctx);
  if (result > 0)
    result = EVP_PKEY_decrypt(ctx, out, &olen, in, inlen);
  EVP_PKEY_CTX_free(ctx);

  if(result <= 0)
    return -EFAULT;
  return (int)olen;
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
  RockeyPKEY_Initialize();

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

/**
 *!
 */
rLANG_ABIREQUIRE(sizeof(XIdRockeyPKEY) == 2 && std::is_unsigned_v<XIdRockeyPKEY> == true &&
                 0x10000 == kCountRockeyPKEY);

rLANG_DECLARE_END
