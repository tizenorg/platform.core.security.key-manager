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
 * @file       store.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <memory>

#include <generic-backend/exception.h>
#include <sw-backend/key.h>
#include <sw-backend/store.h>
#include <sw-backend/internals.h>
#include <SWKeyFile.h>
#include <dpl/log/log.h>

namespace {

template <typename T, typename ...Args>
std::unique_ptr<T> make_unique(Args&& ...args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

} // namespace anonymous

namespace CKM {
namespace Crypto {
namespace SW {

namespace
{
const char * const DEVICE_KEY_XSD       = "/usr/share/ckm/sw_key.xsd";
const char * const DEVICE_KEY_SW_FILE   = "/opt/data/ckm/device_key.xml";
}

Store::Store(CryptoBackend backendId)
  : GStore(backendId)
{
    // get the device key if present
    InitialValues::SWKeyFile keyFile(DEVICE_KEY_SW_FILE);
    int rc = keyFile.Validate(DEVICE_KEY_XSD);
    if(rc == XML::Parser::PARSE_SUCCESS)
    {
        rc = keyFile.Parse();
        if(rc == XML::Parser::PARSE_SUCCESS)
            m_deviceKey = keyFile.getPrivKey();
        else
        {
            // do nothing, bypass encrypted elements
            LogWarning("invalid SW key file: " << DEVICE_KEY_SW_FILE << ", parsing code: " << rc);
        }
    }
    else
        LogWarning("invalid SW key file: " << DEVICE_KEY_SW_FILE << ", validation code: " << rc);
}

GKeyUPtr Store::getKey(const Token &token) {
    if (token.backendId != m_backendId) {
        ThrowErr(Exc::Crypto::WrongBackend, "Decider choose wrong backend!");
    }

    if (token.dataType.isKeyPrivate() || token.dataType.isKeyPublic()) {
         return make_unique<AKey>(token.data, token.dataType);
    }

    if (token.dataType == DataType(DataType::KEY_AES)) {
         return make_unique<SKey>(token.data, token.dataType);
    }

    if (token.dataType.isCertificate()) {
        return make_unique<Cert>(token.data, token.dataType);
    }

    ThrowErr(Exc::Crypto::KeyNotSupported,
        "This type of data is not supported by openssl backend: ", (int)token.dataType);
}

TokenPair Store::generateAKey(const CryptoAlgorithm &algorithm)
{
    return Internals::generateAKey(m_backendId, algorithm);
}

Token Store::generateSKey(const CryptoAlgorithm &algorithm)
{
    return Internals::generateSKey(m_backendId, algorithm);
}

Token Store::import(DataType dataType, const RawBuffer &buffer, const IStorePolicy &policy) {

    if(policy.isEncrypted())
    {
        if(!m_deviceKey)
            ThrowErr(Exc::Crypto::InternalError, "No device key present");

        // decrypt the AES key using device key
        CryptoAlgorithm algorithmRSAOAEP;
        algorithmRSAOAEP.setParam(ParamName::ALGO_TYPE, AlgoType::RSA_OAEP);
        Crypto::SW::SKey AES_key = Crypto::SW::SKey(m_deviceKey->decrypt(algorithmRSAOAEP, policy.getEncryptedKey()), DataType::KEY_AES);

        // decrypt the buffer using AES key
        CryptoAlgorithm algorithmAESCBC;
        algorithmAESCBC.setParam(ParamName::ALGO_TYPE, AlgoType::AES_CBC);
        algorithmAESCBC.setParam(ParamName::ED_IV, policy.getEncryptionIV());
        RawBuffer rawData = AES_key.decrypt(algorithmAESCBC, buffer);

        return Token(m_backendId, dataType, rawData);
    }
    else return Token(m_backendId, dataType, buffer);
}

} // namespace SW
} // namespace Crypto
} // namespace CKM

