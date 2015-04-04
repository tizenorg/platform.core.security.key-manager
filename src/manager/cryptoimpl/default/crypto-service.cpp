#include <iostream>
#include <exception>
#include <vector>
#include <fstream>
#include <string.h>
#include <memory>

#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>
#include <key-impl.h>
#include <crypto-service.h>
#include <crypto-service-openssl.h>
#include <assert.h>
#include <dpl/log/log.h>

#define OPENSSL_SUCCESS 1       // DO NOTCHANGE THIS VALUE
#define OPENSSL_FAIL    0       // DO NOTCHANGE THIS VALUE

namespace CKM {

CryptoService::CryptoService(){
}

CryptoService::~CryptoService(){
}



int CryptoService::initialize() {
    return CryptoServiceOpenssl::initialize();
}

int CryptoService::createKeyPairRSA(const int size, // size in bits [1024, 2048, 4096]
        AsymKeyImplShPtr &createdPrivateKey,  // returned value
        AsymKeyImplShPtr &createdPublicKey)  // returned value
{
    return CryptoServiceOpenssl::createKeyPairRSA(size, createdPrivateKey, createdPublicKey);
}


int CryptoService::createKeyPairDSA(const int size, // size in bits [1024, 2048, 3072, 4096]
		AsymKeyImplShPtr &createdPrivateKey,  // returned value
		AsymKeyImplShPtr &createdPublicKey)  // returned value
{
    return CryptoServiceOpenssl::createKeyPairDSA(size, createdPrivateKey, createdPublicKey);
}


int CryptoService::createKeyPairECDSA(ElipticCurve type,
        AsymKeyImplShPtr &createdPrivateKey,  // returned value
        AsymKeyImplShPtr &createdPublicKey)  // returned value
{
    return CryptoServiceOpenssl::createKeyPairECDSA(type, createdPrivateKey, createdPublicKey);
}

int CryptoService::createSignature(const AsymKeyImplShPtr &privateKey,
        const RawBuffer &message,
        const HashAlgorithm hashAlgo,
        const RSAPaddingAlgorithm padAlgo,
        RawBuffer &signature)
{
    return CryptoServiceOpenssl::createSignature(privateKey, message, hashAlgo, padAlgo, signature);
}

int CryptoService::verifySignature(const AsymKeyImplShPtr &publicKey,
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hashAlgo,
        const RSAPaddingAlgorithm padAlgo)
{
    return CryptoServiceOpenssl::verifySignature(publicKey, message, signature, hashAlgo, padAlgo);
}

}
