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
 * @file        crypto-service.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Asymmetric key pair related crypto service.
 */
#pragma once

#include <ckm/ckm-type.h>
#include <key-impl.h>
#include <dpl/exception.h>

#define DEV_HW_RANDOM_FILE "/dev/hwrng"
#define DEV_URANDOM_FILE   "/dev/urandom"

#define EVP_SUCCESS 1
#define EVP_FAIL    0

#define CKM_CRYPTO_CREATEKEY_SUCCESS  2
#define CKM_VERIFY_CHAIN_SUCCESS      5
#define NOT_DEFINED                  -1

namespace CKM {

 // This is internal api so all functions should throw exception on errors.
class CryptoService {
public:
    CryptoService();
    virtual ~CryptoService();

    class Exception {
        public:
            DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
            DECLARE_EXCEPTION_TYPE(Base, Crypto_internal);
            DECLARE_EXCEPTION_TYPE(Base, opensslError);
    };

    // During initialization, FIPS_MODE and the antropy source are set.
    // And system certificates are loaded in the memory during initialization.
    //    FIPS_MODE - ON, OFF(Default)
    //    antropy source - /dev/random,/dev/urandom(Default)
    static void initialize();

    static int createKeyPairRSA(const int size,      // bits [1024|2048|4096]
                                AsymKeyImpl &priKey,
                                AsymKeyImpl &pubKey);

    static int createKeyPairDSA(const int size,      // bits [1024|2048|3072|4096]
                                AsymKeyImpl &priKey,
                                AsymKeyImpl &pubKey);

    static int createKeyPairECDSA(ElipticCurve type,
                                  AsymKeyImpl &priKey,
                                  AsymKeyImpl &pubKey);

    static int createSignature(const AsymKeyImpl &priKey,
                               const RawBuffer &message,
                               const HashAlgorithm hashAlgo,
                               const RSAPaddingAlgorithm padAlgo,
                               RawBuffer &signature);

    static int verifySignature(const AsymKeyImpl &pubKey,
                               const RawBuffer &message,
                               const RawBuffer &signature,
                               const HashAlgorithm hashAlgo,
                               const RSAPaddingAlgorithm padAlgo);
};

}
