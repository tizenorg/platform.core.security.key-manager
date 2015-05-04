#pragma once

#include <memory>

#include <generic-backend/exception.h>
#include <generic-backend/generic-key.h>
#include <generic-backend/id.h>
#include <generic-backend/token.h>
#include <ckm/ckm-type.h>

namespace CKM {
namespace Crypto {

class GenericStore {
public:
    virtual Id getBackendId() { Throw(Exception::OperationNotSupported); }
    virtual KeyShPtr getKey(const Token &) { Throw(Exception::OperationNotSupported); }
    virtual TokenPair generateAKey(const CryptoAlgorithm &) { Throw(Exception::OperationNotSupported); }
    virtual Token generateSKey(const CryptoAlgorithm &) { Throw(Exception::OperationNotSupported); }
    virtual Token import(KeyType, const RawBuffer &) { Throw(Exception::OperationNotSupported); }
    virtual void destroy(const Token &) { Throw(Exception::OperationNotSupported); }
    virtual ~GenericStore() {}
};

typedef std::shared_ptr<GenericStore> StoreShPtr;

} // namespace Crypto
} // namespace CKM

