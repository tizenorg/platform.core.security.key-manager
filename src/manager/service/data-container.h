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
 * @file       data-container.h
 * @author     Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version    1.0
 */

#pragma once

#include <data-type.h>
#include <ckm/ckm-raw-buffer.h>
#include <generic-backend/istoredata.h>

namespace CKM {

class DataContainer : public Crypto::IStoreData {
public:
    DataContainer() {}
    explicit DataContainer(const CKM::DataType type,
                           const CKM::RawBuffer & data)
        : m_type(type), m_data(data) {}
    const CKM::DataType getType() const {
        return m_type;
    }
    const CKM::RawBuffer & getData() const {
        return m_data;
    }
private:
    CKM::DataType  m_type;
    CKM::RawBuffer m_data;
};

class DataEncryption : public Crypto::IStoreDataEncryption {
public:
    DataEncryption() {}
    explicit DataEncryption(const CKM::RawBuffer & encryptedKey,
                            const CKM::RawBuffer & encryptionIV) :
        m_encryptedKey(encryptedKey),
        m_IV(encryptionIV)
    {}

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
