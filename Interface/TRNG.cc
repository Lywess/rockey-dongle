#include <Interface/dongle.h>

rLANG_DECLARE_MACHINE

namespace dongle {

/**
 *! TRNG 降级语义(设计接受, R1):
 *! - 硬件随机(HwARandBytes/get_random)不可用时, 本函数仍会输出
 *!   "状态⊕密钥流" 的确定性数据, 但返回 -EFAULT —— 此时输出对
 *!   知道 DRBG 状态者完全可预测, 且熵反馈只有 SHA512(公开输出)。
 *! - Ed25519 签名使用确定性 nonce(SHA512 派生), 不调用本函数,
 *!   不受 TRNG 状态影响, 可安全使用。
 *! - 使用非 Ed25519 签名/密钥生成(RSA/SM2/P256/Secp256k1 ECDSA、
 *!   X25519、随机填充)的调用方 ***必须*** 检查本函数的返回值:
 *!   返回 -EFAULT 时禁止把输出当作秘密使用(降级为可预测 PRNG)。
 *!   当前调用方(curves.cc uECC RNG 包装、curve25519.cc 密钥生成、
 *!   master.cc 主密钥更新)均已检查; 新增调用点必须保持该模式。
 */
int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  const size_t size_total = size;
  uint8_t* p = buffer;
  int error = 0;

  union {
    uint8_t stream[64];
    uint32_t v_i32[16];
  };

  while (size >= 64) {
    int result = HwARandBytes(p, 64);
    if (0 != result)
      ++error;
    ++entropy_local_[15];
    rlCryptoChaCha20Block(entropy_local_, stream);
    for (size_t i = 0; i < 64; ++i)
      p[i] ^= stream[i];

    p += 64;
    size -= 64;
  }

  if (size > 0) {
    int result = HwARandBytes(p, size);
    if (0 != result)
      ++error;
    ++entropy_local_[15];
    rlCryptoChaCha20Block(entropy_local_, stream);
    for (size_t i = 0; i < size; ++i)
      p[i] ^= stream[i];
  }

  SHA512(buffer, size_total, stream);
  for (int i = 0; i < 16; ++i)
    entropy_local_[i] += v_i32[i];

  if (0 != error) {
    rlLOGE(rLANG_DECLARE_MAGIC_Xs("$TRNG"), "[**FATAL**]TRNG.error %d", error);
    return -EFAULT;
  }

  return 0;
}

}  // namespace dongle

rLANG_DECLARE_END
