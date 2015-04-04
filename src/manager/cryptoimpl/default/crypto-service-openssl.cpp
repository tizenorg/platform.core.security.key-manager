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
 *
 *
 * @file        crypto-service-openssl.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Asymmetric key pair related crypto service
 *              implemented by using openssl
 */
#include <crypto-service.h>

#include <ckm/ckm-type.h>
#include <ckm/ckm-error.h>
#include <dpl/log/log.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#include <fstream>

namespace {

const EVP_MD *getMdAlgo(const CKM::HashAlgorithm hashAlgo)
{
    switch (hashAlgo) {
    case CKM::HashAlgorithm::NONE:
        return NULL;
    case CKM::HashAlgorithm::SHA1:
        return EVP_sha1();
    case CKM::HashAlgorithm::SHA256:
        return EVP_sha256();
    case CKM::HashAlgorithm::SHA384:
        return EVP_sha384();
    case CKM::HashAlgorithm::SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

int getRsaPadding(const CKM::RSAPaddingAlgorithm padAlgo)
{
    switch (padAlgo) {
    case CKM::RSAPaddingAlgorithm::NONE:
        return RSA_NO_PADDING;
    case CKM::RSAPaddingAlgorithm::PKCS1:
        return RSA_PKCS1_PADDING;
    case CKM::RSAPaddingAlgorithm::X931:
        return RSA_X931_PADDING;
    default:
        return NOT_DEFINED;
    }
}

int signMessage(EVP_PKEY *priKey,
                const CKM::RawBuffer &message,
                const int rsa_padding,
                CKM::RawBuffer &signature)
{
    int retCode = CKM_API_SUCCESS;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        if (!(pctx = EVP_PKEY_CTX_new(priKey, NULL))) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new function");
        }

        if (EVP_PKEY_sign_init(pctx) != EVP_SUCCESS) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_sign_init function");
        }

        /* Set padding algorithm */
        if (EVP_PKEY_RSA == EVP_PKEY_type(priKey->type)
            && EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }

        /* Finalize the Sign operation */

        /* First call EVP_PKEY_sign with a NULL sig parameter
         * to obtain the length of the signature.
         * Length is returned in slen */
        size_t slen;
        if (EVP_PKEY_sign(pctx,
                          NULL,
                          &slen,
                          message.data(),
                          message.size()) != EVP_SUCCESS) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_sign function");
        }

        /* Allocate memory for the signature based on size in slen */
        unsigned char sig[slen];

        if (EVP_PKEY_sign(pctx,
                          sig,
                          &slen,
                          message.data(),
                          message.size()) != EVP_SUCCESS) {
            LogError("Error in EVP_PKEY_sign function: check input parameter");
            retCode = CKM_API_ERROR_INPUT_PARAM;
        } else {
            // Set value to return RawData
            signature.assign(sig, sig+slen);
            retCode = CKM_API_SUCCESS;
        }
    } Catch(CKM::CryptoService::Exception::opensslError) {
        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }
        ReThrowMsg(CKM::CryptoService::Exception::opensslError,
                   "Error in openssl function !!");
    }

    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    return retCode;
}

int digestSignMessage(EVP_PKEY *priKey,
                      const CKM::RawBuffer &message,
                      const EVP_MD *md_algo,
                      const int rsa_padding,
                      CKM::RawBuffer &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        // Create the Message Digest Context
        if (!(mdctx = EVP_MD_CTX_create())) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_MD_CTX_create function");
        }

        if (EVP_SUCCESS != EVP_DigestSignInit(mdctx, &pctx, md_algo, NULL, priKey)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_DigestSignInit function");
        }

        /* Set padding algorithm */
        if (EVP_PKEY_RSA == EVP_PKEY_type(priKey->type)
            && EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }

        /* Call update with the message */
        if (EVP_SUCCESS != EVP_DigestSignUpdate(mdctx,
                                                message.data(),
                                                message.size())) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_DigestSignUpdate function");
        }

        /* Finalize the DigestSign operation */

        /* First call EVP_DigestSignFinal with a NULL sig parameter
         * to obtain the length of the signature.
         * Length is returned in slen */
        size_t slen;
        if (EVP_SUCCESS != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_DigestSignFinal function");
        }
        /* Allocate memory for the signature based on size in slen */
        unsigned char sig[slen];

        /* Obtain the signature */
        if (EVP_SUCCESS != EVP_DigestSignFinal(mdctx, sig, &slen)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_DigestSignFinal function");
        }

        // Set value to return RawData
        signature.assign(sig, sig+slen);
    } Catch (CKM::CryptoService::Exception::opensslError) {

        if (mdctx) {
            EVP_MD_CTX_destroy(mdctx);
        }

        ReThrowMsg(CKM::CryptoService::Exception::opensslError,
                   "Error in openssl function !!");
    }

    // TODO: mdctx to be contained in smart pointer,
    // so it can be destroyed automatically
    if (mdctx) {
        EVP_MD_CTX_destroy(mdctx);
    }

    return CKM_API_SUCCESS;
}

int verifyMessage(EVP_PKEY *pubKey,
                  const CKM::RawBuffer &message,
                  const CKM::RawBuffer &signature,
                  const int rsa_padding)
{
    int ret = CKM_API_ERROR_VERIFICATION_FAILED;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        if(!(pctx = EVP_PKEY_CTX_new(pubKey, NULL))) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new function");
        }

        if(EVP_PKEY_verify_init(pctx) != EVP_SUCCESS) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_verify_init function");
        }

        /* Set padding algorithm  */
        if (EVP_PKEY_RSA == EVP_PKEY_type(pubKey->type)
            && EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }

        if (EVP_PKEY_verify(pctx,
                            signature.data(),
                            signature.size(),
                            message.data(),
                            message.size()) != EVP_SUCCESS) {
            LogError("EVP_PKEY_verify Failed");
            ret = CKM_API_ERROR_VERIFICATION_FAILED;
        } else {
            ret = CKM_API_SUCCESS;
        }
    } Catch (CKM::CryptoService::Exception::opensslError) {
        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }

        ReThrowMsg(CKM::CryptoService::Exception::opensslError,
                   "Error in openssl function !!");
    }

    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    return ret;
}

int digestVerifyMessage(EVP_PKEY *pubKey,
                        const CKM::RawBuffer &message,
                        const CKM::RawBuffer &signature,
                        const EVP_MD *md_algo,
                        const int rsa_padding)
{
    int ret = CKM_API_ERROR_VERIFICATION_FAILED;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        /* Create the Message Digest Context */
        if (!(mdctx = EVP_MD_CTX_create())) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_MD_CTX_create function");
        }

        if (EVP_DigestVerifyInit(mdctx,
                                 &pctx,
                                 md_algo,
                                 NULL,
                                 pubKey) != EVP_SUCCESS) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_DigestVerifyInit function");
        }

        if (EVP_PKEY_RSA == EVP_PKEY_type(pubKey->type)
            && EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }

        if (EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx,
                                                  message.data(),
                                                  message.size()) ) {
            ThrowMsg(CKM::CryptoService::Exception::opensslError,
                     "Error in EVP_DigestVerifyUpdate function");
        }

        // TODO: remove const_cast
        if (EVP_SUCCESS == EVP_DigestVerifyFinal(mdctx, const_cast<unsigned char*>(signature.data()), signature.size()) ) {
            ret = CKM_API_SUCCESS;
        } else {
            LogError("EVP_PKEY_verify Failed");
            ret = CKM_API_ERROR_VERIFICATION_FAILED;
        }
    } Catch (CKM::CryptoService::Exception::opensslError) {
        if (mdctx) {
            EVP_MD_CTX_destroy(mdctx);
        }
        ReThrowMsg(CKM::CryptoService::Exception::opensslError,
                   "Error in openssl function !!");
    }

    if (mdctx) {
        EVP_MD_CTX_destroy(mdctx);
    }

    return ret;
}

} // anonymous namespace


namespace CKM {

CryptoService::CryptoService() {}

CryptoService::~CryptoService() {} 

void CryptoService::initialize()
{
    int hw_rand_ret = 0;
    int u_rand_ret = 0;

    // try to initialize using ERR_load_crypto_strings and OpenSSL_add_all_algorithms
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // initialize entropy
    std::ifstream ifile(DEV_HW_RANDOM_FILE);
    if(ifile.is_open()) {
        u_rand_ret= RAND_load_file(DEV_HW_RANDOM_FILE, 32);
    }
    if(u_rand_ret != 32 ){
        LogError("Error in HW_RAND file load");
        hw_rand_ret = RAND_load_file(DEV_URANDOM_FILE, 32);

        if(hw_rand_ret != 32) {
            LogError("Error in U_RAND_file_load");
            ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in U_RAND_file_load");
        }
    }
}



int CryptoService::createKeyPairRSA(int size, // bit. [1024|2048|4096]
                                    AsymKeyImpl &priKey,
                                    AsymKeyImpl &pubKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pparam = NULL;

    // check the parameters of functions
    if (size != 1024
        && size != 2048
        && size != 4096) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Error in RSA input size");
    }

    Try {
        if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new_id function !!");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_keygen_init function !!");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,size) <= 0) {
            ThrowMsg(CryptoService::Exception::opensslError,
            "Error in EVP_PKEY_CTX_set_rsa_keygen_bits function !!");
        }

        if (!EVP_PKEY_keygen(ctx, &pkey)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_keygen function !!");
        }
    } Catch (CryptoService::Exception::opensslError) {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }

        if (pparam) {
            EVP_PKEY_free(pparam);
        }

        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }

        ReThrowMsg(CryptoService::Exception::opensslError,
                   "Error in opensslError function !!");
    }

    EvpShPtr ptr(pkey, EVP_PKEY_free);

    priKey = AsymKeyImpl(ptr, KeyType::KEY_RSA_PRIVATE);
    pubKey = AsymKeyImpl(ptr, KeyType::KEY_RSA_PUBLIC);

    if (pparam) {
        EVP_PKEY_free(pparam);
    }

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return CKM_CRYPTO_CREATEKEY_SUCCESS;
}


int CryptoService::createKeyPairDSA(int size, // [1024|2048|3072|4096]
                                    AsymKeyImpl &priKey,
                                    AsymKeyImpl &pubKey)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pparam = NULL;

    if (size != 1024
        && size != 2048
        && size != 3072
        && size != 4096) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Error in DSA input size");
    }

    Try {
        /* Create the context for generating the parameters */
        if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL))) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new_id function");
        }

        if (EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_paramgen_init function");
        }

        if (EVP_SUCCESS != EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, size)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_set_dsa_paramgen_bits("
                     << size << ") function");
        }

        /* Generate parameters */
        if (EVP_SUCCESS != EVP_PKEY_paramgen(pctx, &pparam)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_paramgen function");
        }

        // Start to generate key
        if (!(kctx = EVP_PKEY_CTX_new(pparam, NULL))) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new function");
        }

        if (EVP_SUCCESS != EVP_PKEY_keygen_init(kctx)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_keygen_init function");
        }

        /* Generate the key */
        if (EVP_SUCCESS != EVP_PKEY_keygen(kctx, &pkey)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_keygen function");
        }
    }
    Catch(CryptoService::Exception::opensslError)
    {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }

        if (pparam) {
            EVP_PKEY_free(pparam);
        }

        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }

        if (kctx) {
            EVP_PKEY_CTX_free(kctx);
        }

        ReThrowMsg(CryptoService::Exception::opensslError,
                   "Error in openssl function !!");
    }

    EvpShPtr ptr(pkey, EVP_PKEY_free);

    priKey = AsymKeyImpl(ptr, KeyType::KEY_DSA_PRIVATE);
    pubKey = AsymKeyImpl(ptr, KeyType::KEY_DSA_PUBLIC);

    if (pparam) {
        EVP_PKEY_free(pparam);
    }

    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    if (kctx) {
        EVP_PKEY_CTX_free(kctx);
    }

    return CKM_CRYPTO_CREATEKEY_SUCCESS;
}


int CryptoService::createKeyPairECDSA(ElipticCurve type,
                                      AsymKeyImpl &priKey,
                                      AsymKeyImpl &pubKey)
{
    int ecCurve = NOT_DEFINED;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pparam = NULL;

    switch(type) {
    case ElipticCurve::prime192v1:
        ecCurve = NID_X9_62_prime192v1;
        break;
    case ElipticCurve::prime256v1:
        ecCurve = NID_X9_62_prime256v1;
        break;
    case ElipticCurve::secp384r1:
        ecCurve = NID_secp384r1;
        break;
    default:
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Error in EC type");
    }

    Try {
        /* Create the context for generating the parameters */
        if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new_id function");
        }

        if (EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_paramgen_init function");
        }

        if (EVP_SUCCESS != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ecCurve)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid function");
        }

        /* Generate parameters */
        if (EVP_SUCCESS != EVP_PKEY_paramgen(pctx, &pparam)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_paramgen function");
        }

        // Start to generate key
        if (!(kctx = EVP_PKEY_CTX_new(pparam, NULL))) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_CTX_new function");
        }

        if (EVP_SUCCESS != EVP_PKEY_keygen_init(kctx)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_keygen_init function");
        }

        /* Generate the key */
        if (EVP_SUCCESS != EVP_PKEY_keygen(kctx, &pkey)) {
            ThrowMsg(CryptoService::Exception::opensslError,
                     "Error in EVP_PKEY_keygen function");
        }
    } Catch(CryptoService::Exception::opensslError) {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }

        if (pparam) {
            EVP_PKEY_free(pparam);
        }

        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }

        if (kctx) {
            EVP_PKEY_CTX_free(kctx);
        }

        ReThrowMsg(CryptoService::Exception::opensslError,
                   "Error in openssl function !!");
    }

    EvpShPtr ptr(pkey, EVP_PKEY_free);

    priKey = AsymKeyImpl(ptr, KeyType::KEY_ECDSA_PRIVATE);
    pubKey = AsymKeyImpl(ptr, KeyType::KEY_ECDSA_PUBLIC);

    if (pparam) {
        EVP_PKEY_free(pparam);
    }

    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    if (kctx) {
        EVP_PKEY_CTX_free(kctx);
    }

    return CKM_CRYPTO_CREATEKEY_SUCCESS;
}

int CryptoService::createSignature(const AsymKeyImpl &priKey,
                                   const RawBuffer &message,
                                   const HashAlgorithm hashAlgo,
                                   const RSAPaddingAlgorithm padAlgo,
                                   RawBuffer &signature)
{
    int rsa_padding = NOT_DEFINED;
    const EVP_MD *md_algo = NULL;

    if (!(md_algo = getMdAlgo(hashAlgo))) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Invalid Hash algorithm");
    }

    if ((priKey.getType() != KeyType::KEY_RSA_PRIVATE)
       && (priKey.getType() != KeyType::KEY_DSA_PRIVATE)
       && (priKey.getType() != KeyType::KEY_ECDSA_PRIVATE)) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Error in private key type");
    }

    if (priKey.getType() == KeyType::KEY_RSA_PRIVATE
        && NOT_DEFINED == (rsa_padding = getRsaPadding(padAlgo))) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Invalid RSA hash algorithm");
    }

    auto shrPKey = priKey.getEvpShPtr();
    if (!shrPKey) {
        ThrowMsg(CryptoService::Exception::opensslError,
                 "Error in EVP_PKEY_keygen function");
    }

    if (!md_algo) {
        return signMessage(shrPKey.get(),
                           message,
                           rsa_padding,
                           signature);
    }

    return digestSignMessage(shrPKey.get(),
                             message,
                             md_algo,
                             rsa_padding,
                             signature);
}



int CryptoService::verifySignature(const AsymKeyImpl &pubKey,
                                   const RawBuffer &message,
                                   const RawBuffer &signature,
                                   const HashAlgorithm hashAlgo,
                                   const RSAPaddingAlgorithm padAlgo)
{
    int rsa_padding = NOT_DEFINED;
    const EVP_MD *md_algo;

    if (!(md_algo = getMdAlgo(hashAlgo))) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Invalid Hash algorithm");
    }

    if((pubKey.getType() != KeyType::KEY_RSA_PUBLIC)
       && (pubKey.getType() != KeyType::KEY_DSA_PUBLIC)
       && (pubKey.getType() != KeyType::KEY_ECDSA_PUBLIC)) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Error in private key type");
    }

    if (pubKey.getType() == KeyType::KEY_RSA_PUBLIC
        && NOT_DEFINED == (rsa_padding = getRsaPadding(padAlgo))) {
        ThrowMsg(CryptoService::Exception::Crypto_internal,
                 "Invalid RSA hash algorithm");
    }

    auto shrPKey = pubKey.getEvpShPtr();
    if (!shrPKey) {
        ThrowMsg(CryptoService::Exception::opensslError,
                 "Error in getEvpShPtr function");
    }

    if (!md_algo) {
        return verifyMessage(shrPKey.get(),
                             message,
                             signature,
                             rsa_padding);
    }

    return digestVerifyMessage(shrPKey.get(),
                               message,
                               signature,
                               md_algo,
                               rsa_padding);
}

}
