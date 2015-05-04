#pragma once
#include <memory>

#include <openssl/evp.h>

#include <generic-backend/generic-key.h>

namespace CKM {
namespace Crypto {
namespace OpenSSL {

typedef std::unique_ptr<EVP_PKEY_CTX,std::function<void(EVP_PKEY_CTX*)>> ContextUPtr;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;

class SKey : public GenericKey {
public:
    SKey(RawBuffer buffer, KeyType keyType)
      : m_key(std::move(buffer))
      , m_type(keyType)
    {}
protected:
    RawBuffer m_key;
    KeyType m_type;
};

class AKey : public GenericKey {
public:
    AKey(RawBuffer buffer, KeyType keyType)
      : m_key(std::move(buffer))
      , m_type(keyType)
    {}
    virtual RawBuffer sign(const CryptoAlgorithm &alg, const RawBuffer &message);
    virtual ~AKey(){}
protected:
    virtual EvpShPtr getEvpShPtr();
    virtual void setParams(const CryptoAlgorithm &alg, ContextUPtr &context);

    EvpShPtr m_evp;
    RawBuffer m_key;
    KeyType m_type;
};

} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM

