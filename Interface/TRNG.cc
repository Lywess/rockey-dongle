#include <Interface/dongle.h>

rLANG_DECLARE_MACHINE

namespace dongle {

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
