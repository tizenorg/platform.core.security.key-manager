#pragma once
#include <memory>

#include <ckm/ckm-raw-buffer.h>
#include <ckm/ckm-type.h>

/* TODO remove define */
#define NotSupported 1

namespace CKM {
namespace Crypto {

/* TODO remove class definition */
struct CryptoAlgorithm {
    int i;
};

class GenericKey {
public:
    virtual RawBuffer getBinary() {
        throw NotSupported;
    }
    
    virtual RawBuffer encrypt(const CryptoAlgorithm &, const RawBuffer &) {
        throw NotSupported;
    }
    
    virtual RawBuffer decrypt(const CryptoAlgorithm &, const RawBuffer &) {
        throw NotSupported;
    }

    virtual RawBuffer sign(const CryptoAlgorithm &, const RawBuffer &) {
        throw NotSupported;
    }

    virtual RawBuffer verify(const CryptoAlgorithm &, const RawBuffer &) {
        throw NotSupported;
    }

    virtual ~GenericKey () {}
};

typedef std::shared_ptr<GenericKey> KeyShPtr;

} // namespace Crypto
} // namespace CKM

