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

namespace CKM {
namespace Crypto {
namespace SW {

Store::Store(CryptoBackend backendId)
  : GStore(backendId)
{
    // initialize openssl internals
    Internals::initialize();
}

GKeyShPtr Store::getKey(const Token &token) {
    if (token.backendId != m_backendId) {
        ThrowErr(Exc::Crypto::WrongBackend, "Decider choose wrong backend!");
    }

    if (token.dataType.isKeyPrivate() || token.dataType.isKeyPublic()) {
         return std::make_shared<AKey>(token.data, token.dataType);
    }

    if (token.dataType == DataType(DataType::KEY_AES)) {
         return std::make_shared<SKey>(token.data, token.dataType);
    }

    if (token.dataType.isCertificate()) {
        return std::make_shared<Cert>(token.data, token.dataType);
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

Token Store::import(DataType dataType, const RawBuffer &buffer) {
    return Token(m_backendId, dataType, buffer);
}

} // namespace SW
} // namespace Crypto
} // namespace CKM

