/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       key.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <memory>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <sw-backend/key.h>

#define EVP_SUCCESS 1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL    0	// DO NOTCHANGE THIS VALUE

namespace CKM {
namespace Crypto {
namespace SW {

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

} // namespace SW
} // namespace Crypto
} // namespace CKM

