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

 // typedef std::vector<unsigned char> RawData; this must be defined in common header.
 // This is internal api so all functions should throw exception on errors.
class CryptoServiceOpenssl {
public:
    CryptoServiceOpenssl();
    virtual ~CryptoServiceOpenssl();

    // During initialization, FIPS_MODE and the antropy source are set.
    // And system certificates are loaded in the memory during initialization.
    //    FIPS_MODE - ON, OFF(Default)
    //    antropy source - /dev/random,/dev/urandom(Default)
    static int initialize();

    static int createKeyPairRSA(const int size,      // size in bits [1024, 2048, 4096]
                        AsymKeyImplShPtr &createdPrivateKey,  // returned value ==> Key &createdPrivateKey,
                        AsymKeyImplShPtr &createdPublicKey);  // returned value ==> Key &createdPublicKey

    static int createKeyPairDSA(const int size,      // size in bits [1024, 2048, 3072, 4096]
                        AsymKeyImplShPtr &createdPrivateKey,  // returned value ==> Key &createdPrivateKey,
                        AsymKeyImplShPtr &createdPublicKey);  // returned value ==> Key &createdPublicKey

    static int createKeyPairECDSA(ElipticCurve type1,
                        AsymKeyImplShPtr &createdPrivateKey,  // returned value
                        AsymKeyImplShPtr &createdPublicKey);  // returned value

    static int createSignature(const AsymKeyImplShPtr &privateKey,
                        const RawBuffer &message,
                        const HashAlgorithm hashAlgo,
                        const RSAPaddingAlgorithm padAlgo,
                        RawBuffer &signature);

    static int verifySignature(const AsymKeyImplShPtr &publicKey,
                        const RawBuffer &message,
                        const RawBuffer &signature,
                        const HashAlgorithm hashAlgo,
                        const RSAPaddingAlgorithm padAlgo);

private:

    static const EVP_MD *getMdAlgo(const HashAlgorithm hashAlgo);
    static int getRsaPadding(const RSAPaddingAlgorithm padAlgo);

    static int signMessage(EVP_PKEY *privKey,
            const RawBuffer &message,
            const int rsa_padding,
            RawBuffer &signature);
    static int digestSignMessage(EVP_PKEY *privKey,
            const RawBuffer &message,
            const EVP_MD *md_algo,
            const int rsa_padding,
            RawBuffer &signature);

    static int verifyMessage(EVP_PKEY *pubKey,
            const RawBuffer &message,
            const RawBuffer &signature,
            const int rsa_padding);
    static int digestVerifyMessage(EVP_PKEY *pubKey,
            const RawBuffer &message,
            const RawBuffer &signature,
            const EVP_MD *md_algo,
            const int rsa_padding);
};
}


