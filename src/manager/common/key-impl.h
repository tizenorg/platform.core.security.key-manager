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

    virtual ~KeyImpl() {}

    bool empty() const;

    KeyType     getType() const;
    RawBuffer   getBinary() const;
    bool        isExternalKey() const;

    void        setType(const KeyType& type);
    void        setBinary(const RawBuffer& binary);
    void        setExternalKey(const bool& isExternalKey);

protected:
    KeyType      m_type;
    RawBuffer    m_binary;
    bool         m_external;

    KeyImpl();
    KeyImpl(const KeyType& type, const RawBuffer& binary, const bool& isExternalKey);
    KeyImpl(const KeyImpl& second);
};

class AsymKeyImpl;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;
typedef std::shared_ptr<AsymKeyImpl> AsymKeyImplShPtr;

class COMMON_API AsymKeyImpl : public KeyImpl {
public:
    AsymKeyImpl();
    AsymKeyImpl(const AsymKeyImpl &second);
    AsymKeyImpl(const KeyType& type, const RawBuffer& binary, const bool& isExternalKey);
    AsymKeyImpl(const EvpShPtr& pkey, const KeyType& type);
    AsymKeyImpl(const RawBuffer& binary, const Password &password);

    virtual RawBuffer getDER() const;
    virtual EvpShPtr  getEvpShPtr() const;

    virtual ~AsymKeyImpl() {}
protected:
    virtual RawBuffer toBinary(const KeyType& type, EVP_PKEY* pKey);
};

class SymKeyImpl;
typedef std::shared_ptr<SymKeyImpl> SymKeyImplShPtr;

class COMMON_API SymKeyImpl : public KeyImpl {
public:
    SymKeyImpl();
    SymKeyImpl(const SymKeyImpl &second);
    SymKeyImpl(const KeyType& type, const RawBuffer& binary, const bool& isExternalKey);
    SymKeyImpl(const KeyType& type, const RawBuffer& binary);

    virtual ~SymKeyImpl() {}
};

class COMMON_API KeyBuilder {
public:
    static KeyImplShPtr create(const KeyType& type, const RawBuffer &binary, const Password &password);
    static KeyImplShPtr create(const KeyType& type, const RawBuffer &binary, const bool &isExternalKey = false);
    static AsymKeyImplShPtr create(const EvpShPtr &pkey, const KeyType &type);
    static AsymKeyImplShPtr createNullAsymKey();
    static SymKeyImplShPtr createNullSymKey();
    static KeyImplShPtr toKeyImplShPtr(const KeyShPtr& keyShPtr);
    static void toExternalKey(KeyImplShPtr& pInternalKey, const std::string& externalId);
    static void toInternalKey(KeyImplShPtr& pExternalKey, const RawBuffer& binary);
};

}
