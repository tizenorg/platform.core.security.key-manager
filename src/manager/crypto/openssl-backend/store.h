#pragma once

#include <generic-backend/generic-store.h>
#include <generic-backend/id.h>

namespace CKM {
namespace Crypto {
namespace OpenSSL {

class Store : public GenericStore {
public:
    virtual Id getBackendId();
    static StoreShPtr create();
};

} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM

