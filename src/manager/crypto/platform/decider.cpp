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
 * @file       decider.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <dpl/log/log.h>

#include <crypto-backend.h>

#include <platform/decider.h>

#include <sw-backend/store.h>
#include <tz-backend/store.h>

namespace CKM {
namespace Crypto {

Decider::Decider()
  : m_swStore(new SW::Store(CryptoBackend::OpenSSL))
  , m_tzStore(new TZ::Store(CryptoBackend::TrustZone))
{}

GStore& Decider::getStore(const Token &token) {
    return getStore(token.backendId);
};

GStore& Decider::getStore(CryptoBackend cryptoBackend) {
    GStore *gStore = NULL;
    if (cryptoBackend == CryptoBackend::OpenSSL)
        gStore = m_swStore.get();
    if (cryptoBackend == CryptoBackend::TrustZone)
        gStore = m_tzStore.get();

    if (gStore)
        return *gStore;

    LogError("Backend not available. BackendId: " << (int)cryptoBackend);
    ThrowMsg(CKM::Crypto::Exception::Base,
             "Backend not available. BackendId: " << (int)cryptoBackend);
}

CryptoBackend Decider::chooseCryptoBackend(DataType dataType, const Policy &policy) const {
// The list of items that MUST be support by OpenSSL
    if (dataType.isCertificate())
        return CryptoBackend::OpenSSL;

    if (dataType.isBinaryData())
        return CryptoBackend::OpenSSL;

    if (policy.extractable)
        return CryptoBackend::OpenSSL;

//  This is the place where we can use trust zone backend
//  Examples:
//
//  if (dataType.isKeyPrivate())
//      return CryptoBackend::TrustZone;

// This item does not met Trust Zone requirements. Let's use software backend
    return CryptoBackend::OpenSSL;
}

} // namespace Crypto
} // namespace CKM

