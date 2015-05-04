#include <memory>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <openssl-backend/key.h>

#define EVP_SUCCESS 1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL    0	// DO NOTCHANGE THIS VALUE

namespace CKM {
namespace Crypto {
namespace OpenSSL {

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

RawBuffer AKey::sign(
    const CryptoAlgorithm &alg,
    const RawBuffer &message)
{
    auto key = getEvpShPtr();
    ContextUPtr pctx(EVP_PKEY_CTX_new(key.get(), NULL), EVP_PKEY_CTX_free);

    if(!pctx) {
        LogError("Error in EVP_PKEY_CTX_new function");
        ThrowMsg(Exception::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_PKEY_sign_init(pctx.get()) != EVP_SUCCESS) {
        LogError("Error in EVP_PKEY_sign_init function");
        ThrowMsg(Exception::InternalError, "Error in EVP_PKEY_sign_init function");
    }

    setParams(alg, pctx);

    /* Finalize the Sign operation */
    /* First call EVP_PKEY_sign with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t slen;
    if(EVP_SUCCESS != EVP_PKEY_sign(pctx.get(), NULL, &slen, message.data(), message.size())) {
        LogError("Error in EVP_PKEY_sign function");
        ThrowMsg(Exception::InternalError, "Error in EVP_PKEY_sign function");
    }

    /* Allocate memory for the signature based on size in slen */
    RawBuffer signature(slen);

    if(EVP_SUCCESS == EVP_PKEY_sign(pctx.get(),
                                    signature.data(),
                                    &slen,
                                    message.data(),
                                    message.size()))
    {
        LogError("Error in EVP_PKEY_sign function");
        ThrowMsg(Exception::InternalError, "Error in EVP_PKEY_sign function");
        // Set value to return RawData
    }
    return signature;
}

void AKey::setParams(
    const CryptoAlgorithm &alg,
    ContextUPtr &context)
{
    (void)alg;
    (void)context;
/* TODO extract rsa_padding from alg

    if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx.get(), rsa_padding)) {
        LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
        ThrowMsg(CryptoService::Exception::opensslError,
                 "Error in EVP_PKEY_CTX_set_rsa_padding function");
    }
*/
}

EvpShPtr AKey::getEvpShPtr() {
    if (m_evp)
        return m_evp;

    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    LogDebug("Start to parse key:");

    if (!pkey) {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_key.data(), m_key.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey) {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_key.data(), m_key.size());
        pkey = d2i_PUBKEY_bio(bio.get(), NULL);
        LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
    }

    if (!pkey) {
        LogError("Failed to parse key");
        ThrowMsg(Exception::InternalError, "Failed to parse key");
    }

    m_evp.reset(pkey, EVP_PKEY_free);
    return m_evp;
}

} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM

