#pragma once

#include <iostream>
#include <key-impl.h>
#include <certificate-impl.h>
#include <ckm/ckm-type.h>
#include <vector>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <dpl/exception.h>

#define DEV_HW_RANDOM_FILE    "/dev/hwrng"
#define DEV_URANDOM_FILE    "/dev/urandom"

#define EVP_SUCCESS 1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL    0	// DO NOTCHANGE THIS VALUE

#define CKM_CRYPTO_INIT_SUCCESS 1
#define CKM_CRYPTO_CREATEKEY_SUCCESS 2
#define CKM_VERIFY_CHAIN_SUCCESS 5
#define NOT_DEFINED -1

namespace CKM {
namespace Crypto {
namespace SW {
namespace Internals {

int initialize();

int createKeyPairRSA(const int size,
    KeyImpl &createdPrivateKey,
    KeyImpl &createdPublicKey);

int createKeyPairDSA(const int size,
    KeyImpl &createdPrivateKey,
    KeyImpl &createdPublicKey);

int createKeyPairECDSA(ElipticCurve type1,
    KeyImpl &createdPrivateKey,
    KeyImpl &createdPublicKey);

RawBuffer sign(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message);

int verify(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message,
    const RawBuffer &signature);

const EVP_MD *getMdAlgo(const HashAlgorithm hashAlgo);
int getRsaPadding(const RSAPaddingAlgorithm padAlgo);

int signMessage(EVP_PKEY *privKey,
    const RawBuffer &message,
    const int rsa_padding,
    RawBuffer &signature);

int digestSignMessage(EVP_PKEY *privKey,
    const RawBuffer &message,
    const EVP_MD *md_algo,
    const int rsa_padding,
    RawBuffer &signature);

int verifyMessage(EVP_PKEY *pubKey,
    const RawBuffer &message,
    const RawBuffer &signature,
    const int rsa_padding);

int digestVerifyMessage(EVP_PKEY *pubKey,
    const RawBuffer &message,
    const RawBuffer &signature,
    const EVP_MD *md_algo,
    const int rsa_padding);

} // namespace Internals
} // namespace SW
} // namespace Crypto
} // namespace CKM

