#pragma once

#include <memory>

#include <generic-backend/generic-store.h>
#include <generic-backend/token.h>

namespace CKM {
namespace Crypto {

class Decider {
public:
    Decider();
    StoreShPtr getStore(const Token &token);
    virtual ~Decider(){}
private:
    StoreShPtr m_store;
};

} // Crypto
} // CKM

