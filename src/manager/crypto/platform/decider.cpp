#include <platform/decider.h>

#include <openssl-backend/store.h>

namespace CKM {
namespace Crypto {

Decider::Decider()
  : m_store(new OpenSSL::Store)
{}

StoreShPtr Decider::getStore(const Token &) {
    // This the place where we should choose backend bases on token information.
    return m_store;
};

} // namespace Crypto
} // namespace CKM

