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


enum class KeyFormat : int {
    KFORM_NONE = 0, //
    KFORM_DER,      // for aymmetric key
    KFORM_RAW,      // for symmetric key
    KFORM_EXT_ID    // for keys that are stored outside key-manager DB
};

class KeyImpl;
typedef std::shared_ptr<KeyImpl> KeyImplShPtr;

class COMMON_API KeyImpl : public Key {
public:
    KeyImpl();
    KeyImpl(const KeyType type, const KeyFormat format, const RawBuffer& binary);
    KeyImpl(const KeyImpl &second);
    KeyImpl(const RawBuffer& internalBinary);

    virtual ~KeyImpl() {}

    virtual bool empty() const;
    virtual KeyType getType() const;
    virtual void setType(const KeyType type);
    virtual RawBuffer getBinary() const;
    virtual void setBinary(const RawBuffer& binary);
    virtual KeyFormat getFormat() const;
    virtual void setFormat(const KeyFormat format);
    virtual RawBuffer getInternalBinary() const;
    virtual void setInternalBinary(const RawBuffer& internalBinary);
    virtual void setKeyImpl(const KeyImplShPtr keyImplShPtr);

protected:
    KeyType      m_type;
    KeyFormat    m_format;
    int          m_bin_size;
    RawBuffer    m_binary;

    // to prevent from instantiation of KeyImpl
    virtual bool isVirtual() const =0;
};

class AsymKeyImpl;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;
typedef std::shared_ptr<AsymKeyImpl> AsymKeyImplShPtr;

class COMMON_API AsymKeyImpl : public KeyImpl {
public:
    AsymKeyImpl();
    AsymKeyImpl(const AsymKeyImpl &second);
    AsymKeyImpl(const RawBuffer& internalBinary);
    AsymKeyImpl(const RawBuffer& binary, const Password &password);
    AsymKeyImpl(const EvpShPtr& pkey, const KeyType& type);

    virtual RawBuffer getDER() const;
    virtual RawBuffer getDERPUB() const;
    virtual RawBuffer getDERPRV() const;
    virtual EvpShPtr getEvpShPtr() const;

    virtual void setKeyImpl(const KeyImplShPtr keyImplShPtr);

    virtual ~AsymKeyImpl() {}

protected:
    EvpShPtr m_pkey;

    virtual bool isVirtual() const {return false;}
    virtual void binaryToEvpShPtr(const Password &password = Password());

};

class SymKeyImpl;
typedef std::shared_ptr<SymKeyImpl> SymKeyImplShPtr;

class COMMON_API SymKeyImpl : public KeyImpl {
public:
    SymKeyImpl();
    SymKeyImpl(const SymKeyImpl &second);
    SymKeyImpl(const RawBuffer& internalBinary);
    SymKeyImpl(const RawBuffer& binary, const KeyType type);

    virtual int getSize() const;

    virtual ~SymKeyImpl() {}

protected:
    virtual bool isVirtual() const {return false;}
};

class COMMON_API KeyBuilder {
public:
    static KeyImplShPtr create(const RawBuffer &inBinary);
    static KeyImplShPtr create(const EvpShPtr &pkey, const KeyType &type);
    static KeyImplShPtr create(const KeyType type, const RawBuffer &binary, const Password &password);
    static KeyImplShPtr createNullAsymKey();
    static KeyImplShPtr createNullSymKey();
    static KeyImplShPtr toKeyImplShPtr(KeyShPtr keyShPtr);
};

}
