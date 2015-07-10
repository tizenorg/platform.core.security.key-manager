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
 * @file       internal-policy.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <protocols.h>
#include <dpl/serialization.h>
#include <generic-backend/gstore.h>

namespace CKM {

class InternalPolicy : protected PolicySerializable, public Crypto::IStorePolicy {
public:
    InternalPolicy() : PolicySerializable() {}
    explicit InternalPolicy(bool exportable) : PolicySerializable() {
        extractable = exportable;
    }
    explicit InternalPolicy(const Policy &policy) : PolicySerializable(policy) {}
    explicit InternalPolicy(const Policy &policy,
                            const CKM::RawBuffer & encryptedKey,
                            const CKM::RawBuffer & encryptionIV) :
        PolicySerializable(policy),
        m_encryptedKey(encryptedKey),
        m_IV(encryptionIV)
    {}
    explicit InternalPolicy(IStream &stream) : PolicySerializable(stream) {}

    void Serialize(IStream &stream) const { PolicySerializable::Serialize(stream); }

    Password getPassword() const { return password; }
    bool isExportable() const { return extractable; }
    bool isEncrypted() const { return (m_encryptedKey.size()>0); }
    const CKM::RawBuffer & getEncryptedKey() const {
        return m_encryptedKey;
    }
    const CKM::RawBuffer & getEncryptionIV() const {
        return m_IV;
    }
private:
    CKM::RawBuffer m_encryptedKey;
    CKM::RawBuffer m_IV;
};

} // namespace CKM

