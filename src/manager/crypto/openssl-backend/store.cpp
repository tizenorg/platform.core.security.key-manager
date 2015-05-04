#include <memory>

#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <openssl-backend/key.h>
#include <openssl-backend/store.h>

namespace CKM {
namespace Crypto {
namespace OpenSSL {

Id Store::getBackendId() { return Id::OpenSSL; }

KeyShPtr Store::getKey(const Token &token) {
    if (token.backendId != getBackendId()) {
        LogDebug("Decider choose wrong backend!");
        ThrowMsg(Exception::WrongBackend, "Decider choose wrong backend!");
    }

    KeyShPtr result;
    switch (token.keyType) {
    case KeyType::KEY_RSA_PUBLIC:
    case KeyType::KEY_RSA_PRIVATE:
    case KeyType::KEY_DSA_PUBLIC:
    case KeyType::KEY_DSA_PRIVATE:
    case KeyType::KEY_ECDSA_PUBLIC:
    case KeyType::KEY_ECDSA_PRIVATE:
         return std::make_shared<AKey>(token.buffer, token.keyType);
    case KeyType::KEY_AES:
         return std::make_shared<SKey>(token.buffer, token.keyType);
    default:
         LogDebug(
            "This type of key is not supported by openssl backend: " << (int)token.keyType);
         ThrowMsg(Exception::KeyNotSupported,
            "This type of key is not supported by openssl backend: " << (int)token.keyType);
    }

}

StoreShPtr Store::create() {
    return std::make_shared<Store>();
}

} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM

