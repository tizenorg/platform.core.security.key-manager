#pragma once
#include <memory>

#include <ckm/ckm-raw-buffer.h>
#include <ckm/ckm-type.h>

#include <generic-backend/exception.h>

namespace CKM {
namespace Crypto {

/* TODO remove class definition */
struct CryptoAlgorithm {
    int i;
};

class GenericKey {
public:
    virtual RawBuffer getBinary() {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer encrypt(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer decrypt(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer sign(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer verify(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual ~GenericKey () {}
};

typedef std::shared_ptr<GenericKey> KeyShPtr;

} // namespace Crypto
} // namespace CKM

