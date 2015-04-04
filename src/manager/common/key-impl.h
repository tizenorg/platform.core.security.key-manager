/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        key-impl.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.1
 * @brief       Key implementation.
 */
#pragma once

#include <memory>

#include <ckm/ckm-type.h>
#include <ckm/ckm-key.h>
#include <openssl/evp.h>
#include <symbol-visibility.h>


namespace CKM {

class KeyImpl;
typedef std::shared_ptr<KeyImpl> KeyImplShPtr;

class COMMON_API KeyImpl : public Key {
public:
    KeyImpl(const RawBuffer &keyBuffer,
            const KeyType type,
            const bool isExternalKey = false);

    virtual ~KeyImpl() {}

    bool empty() const;

    KeyType     getType() const;
    RawBuffer   getBinary() const;
    bool        isExternalKey() const;

    void        setType(const KeyType type);
    void        setBinary(const RawBuffer &binary);
    void        setExternalKey(const bool isExternalKey);

    static void toExternalKey(KeyImpl &pInternalKey, const std::string &externalId);
    static void toInternalKey(KeyImpl &pExternalKey, const RawBuffer &binary);

protected:
    KeyType     m_type;
    RawBuffer   m_binary;
    bool        m_external;

    KeyImpl();
    KeyImpl(const KeyImpl &second);
};

class AsymKeyImpl;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;
typedef std::shared_ptr<AsymKeyImpl> AsymKeyImplShPtr;

class COMMON_API AsymKeyImpl : public KeyImpl {
public:
    AsymKeyImpl();
    AsymKeyImpl(const RawBuffer &keyBuffer,
                const KeyType type,
                const bool isExternalKey = false);

    // for Key::create
    AsymKeyImpl(const RawBuffer &keyBuffer,
                const Password &password = Password());

    // for certificate-impl and pkcs-impl
    AsymKeyImpl(EvpShPtr pkey, const KeyType type);

    virtual ~AsymKeyImpl() {}

    virtual EvpShPtr getEvpShPtr() const;

protected:
    virtual void setBinary(EVP_PKEY *pKey);
};

class SymKeyImpl;
typedef std::shared_ptr<SymKeyImpl> SymKeyImplShPtr;

class COMMON_API SymKeyImpl : public KeyImpl {
public:
    SymKeyImpl();
    SymKeyImpl(const RawBuffer &keyBuffer,
               const KeyType type,
               const bool isExternalKey = false);

    virtual ~SymKeyImpl() {}
};
}
