#include <openssl-backend/key.h>

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
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_PKEY_sign_init(pctx.get()) != EVP_SUCCESS) {
        LogError("Error in EVP_PKEY_sign_init function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_sign_init function");
    }

    setParams(alg, pctx);

    /* Finalize the Sign operation */
    /* First call EVP_PKEY_sign with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t slen;
    if(EVP_SUCCESS != EVP_PKEY_sign(pctx.get(), NULL, &slen, message.data(), message.size())) {
        LogError("Error in EVP_PKEY_sign function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_sign function");
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
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_sign function");
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








107     BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
108 
109     LogDebug("Start to parse key:");
110 //    printDER(buf);
111 
112     if (buf[0] != '-') {
113         BIO_write(bio.get(), buf.data(), buf.size());
114         pkey = d2i_PUBKEY_bio(bio.get(), NULL);
115         isPrivate = false;
116         LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
117     }
118 
119     if (!pkey && buf[0] != '-') {
120         (void)BIO_reset(bio.get());
121         BIO_write(bio.get(), buf.data(), buf.size());
122         pkey = d2i_PrivateKey_bio(bio.get(), NULL);
123         isPrivate = true;
124         LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
125     }
126 
127     if (!pkey && buf[0] == '-') {
128         (void)BIO_reset(bio.get());
129         BIO_write(bio.get(), buf.data(), buf.size());
130         pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, passcb, const_cast<Password*>(&password));
131         isPrivate = false;
132         LogDebug("PEM_read_bio_PUBKEY Status: " << (void*)pkey);
133     }
134 
135     if (!pkey && buf[0] == '-') {
136         (void)BIO_reset(bio.get());
137         BIO_write(bio.get(), buf.data(), buf.size());
138         pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, passcb, const_cast<Password*>(&password));
139         isPrivate = true;
140         LogDebug("PEM_read_bio_PrivateKey Status: " << (void*)pkey);
141     }
142 
143     if (!pkey) {
144         LogError("Failed to parse key");
145         return;
146     }
147 
148     m_pkey.reset(pkey, EVP_PKEY_free);
149 






























    m_evp = std::shared_ptr(
}


} // namespace OpenSSL
} // namespace Crypto
} // namespace CKM

