#pragma once
#include <memory>

#include <generic-backend/generic-key.h>

#define NotSupported 1

namespace CKM {
namespace Crypto {
namespace OpenSSL {

typedef std::unique_ptr<EVP_PKEY_CTX> ContextUPtr;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;

class SKey : public GenericKey {
public:
};

class AKey : public GenericKey {
public:
    RawBuffer sign(const CryptoAlgorithm &alg, const RawBuffer &message);
protected:
    virtual EvpShPtr getEvpShPtr();
    virtual void setParams(const CryptoAlgorithm &alg, ContextUPtr &context);
private:
    EvpShPtr m_evp;
    RawBuffer m_key;
    KeyType m_type;
};

} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM

