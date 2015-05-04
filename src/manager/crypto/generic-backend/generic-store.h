#pragma once

#include <memory>

#include <generic-backend/generic-key.h>
#include <generic-backend/id.h>
#include <generic-backend/token.h>
#include <ckm/ckm-type.h>

#define NotSupported 1

namespace CKM {
namespace Crypto {

class GenericStore {
public:
    virtual Id getBackendId() { throw NotSupported; }
    virtual GenericKey getKey(const Token &) { throw NotSupported; }
    virtual TokenPair generateAKey(const CryptoAlgorithm &) { throw NotSupported; }
    virtual Token generateSKey(const CryptoAlgorithm &) { throw NotSupported; }
    virtual Token import(KeyType, const RawBuffer &) { throw NotSupported; }
    virtual void destroy(const Token &) { throw NotSupported; }
    virtual ~GenericStore() {}
};

typedef std::shared_ptr<GenericStore> StoreShPtr;

} // namespace Crypto
} // namespace CKM

