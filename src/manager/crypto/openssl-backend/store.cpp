#include <memory>

#include <openssl-backend/store.h>

namespace CKM {
namespace Crypto {
namespace OpenSSL {

Id Store::getBackendId() { return Id::OpenSSL; }

StoreShPtr Store::create() {
    return std::make_shared<Store>();
}

} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM




