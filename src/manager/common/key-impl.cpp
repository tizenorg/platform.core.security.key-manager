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
 * @file        key-impl.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Key implementation.
 */
#include <string.h>

#include <functional>
#include <memory>
#include <sstream>
#include <ios>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <ckm/ckm-type.h>
#include <key-impl.h>

namespace CKM {
namespace {

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

int passcb(char *buff, int size, int rwflag, void *userdata) {
    (void) rwflag;
    Password *ptr = static_cast<Password*>(userdata);
    if (ptr == NULL)
        return 0;
    if (ptr->empty())
        return 0;
    if (static_cast<int>(ptr->size()) > size)
        return 0;
    memcpy(buff, ptr->c_str(), ptr->size());
    return ptr->size();
}

typedef int(*I2D_CONV)(BIO*, EVP_PKEY*);

CKM::RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey) {
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (NULL == pkey) {
        LogDebug("You are trying to read empty key!");
        return RawBuffer();
    }

    if (NULL == bio.get()) {
        LogError("Error in memory allocation! Function: BIO_new.");
        return RawBuffer();
    }

    if (1 != fun(bio.get(), pkey)) {
        LogError("Error in conversion EVP_PKEY to der");
        return RawBuffer();
    }

    CKM::RawBuffer output(8196);

    int size = BIO_read(bio.get(), output.data(), output.size());

    if (size <= 0) {
        LogError("Error in BIO_read: " << size);
        return RawBuffer();
    }

    output.resize(size);
    return output;
}

} // anonymous namespace

//=============================================
// Implementations of KeyImpl
//=============================================

KeyImpl::KeyImpl()
  : m_type(KeyType::KEY_NONE)
  , m_binary(RawBuffer())
  , m_external(false)
{}

KeyImpl::KeyImpl(const KeyType& type, const RawBuffer& binary, const bool& isExternalKey)
  : m_type(type)
  , m_binary(RawBuffer())
  , m_external(isExternalKey)
{
    m_binary.assign(binary.begin(), binary.end());
}

KeyImpl::KeyImpl(const KeyImpl &second)
  : m_binary(RawBuffer())
{
    m_type     = second.m_type;
    m_external = second.m_external;
    m_binary.assign(second.m_binary.begin(), second.m_binary.end());
}

bool KeyImpl::empty() const {
    return m_binary.empty();
}

KeyType KeyImpl::getType() const {
    return m_type;
}

RawBuffer KeyImpl::getBinary() const {
    return m_binary;
}

bool KeyImpl::isExternalKey() const {
    return m_external;
}

void KeyImpl::setType(const KeyType& type) {
    m_type = type;
}

void KeyImpl::setBinary(const RawBuffer& binary) {
    m_binary.assign(binary.begin(), binary.end());
}

void KeyImpl::setExternalKey(const bool& isExternalKey) {
    m_external = isExternalKey;
}


//=============================================
// Implementations of AsymKeyImpl
//=============================================

AsymKeyImpl::AsymKeyImpl()
  : KeyImpl()
{}

AsymKeyImpl::AsymKeyImpl(const AsymKeyImpl &second)
  : KeyImpl(second)
{}

AsymKeyImpl::AsymKeyImpl(const KeyType& type, const RawBuffer& binary, const bool& isExternalKey)
  : KeyImpl(type, binary, isExternalKey)
{}

AsymKeyImpl::AsymKeyImpl(const EvpShPtr &pkey, const KeyType &type)
  : KeyImpl(type, RawBuffer(), false)
{
    RawBuffer der = toBinary(type, pkey.get());
    m_binary.assign(der.begin(), der.end());
}

AsymKeyImpl::AsymKeyImpl(const RawBuffer& binary, const Password &password)
  : KeyImpl()
{
    bool isPrivate = false;
    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    LogDebug("Start to parse key:");
    if(binary.size() == 0) {
        LogWarning("Fail to convert binary to EVP_PKEY. binary size is 0.");
        return;
    }
//    printDER(binary);

    if (binary[0] != '-') {
        BIO_write(bio.get(), binary.data(), binary.size());
        pkey = d2i_PUBKEY_bio(bio.get(), NULL);
        isPrivate = false;
        LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
    }

    if (!pkey && binary[0] != '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), binary.data(), binary.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        isPrivate = true;
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey && binary[0] == '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), binary.data(), binary.size());
        pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = false;
        LogDebug("PEM_read_bio_PUBKEY Status: " << (void*)pkey);
    }

    if (!pkey && binary[0] == '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), binary.data(), binary.size());
        pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = true;
        LogDebug("PEM_read_bio_PrivateKey Status: " << (void*)pkey);
    }

    if (!pkey) {
        LogError("Failed to parse key");
        return;
    }

    // set Type
    switch(EVP_PKEY_type(pkey->type))
    {
        case EVP_PKEY_RSA:
            m_type = isPrivate ? KeyType::KEY_RSA_PRIVATE : KeyType::KEY_RSA_PUBLIC;
            break;

        case EVP_PKEY_DSA:
            m_type = isPrivate ? KeyType::KEY_DSA_PRIVATE : KeyType::KEY_DSA_PUBLIC;
            break;

        case EVP_PKEY_EC:
            m_type = isPrivate ? KeyType::KEY_ECDSA_PRIVATE : KeyType::KEY_ECDSA_PUBLIC;
            break;
    }

    // set Binary
    RawBuffer der = toBinary(m_type, pkey);
    m_binary.assign(der.begin(), der.end());

    LogDebug("KeyType is: " << (int)m_type << " isPrivate: " << isPrivate << ", size: " << m_binary.size());

    EVP_PKEY_free(pkey);
}

RawBuffer AsymKeyImpl::getDER() const {
    return m_binary;
}

EvpShPtr AsymKeyImpl::getEvpShPtr() const {
    if(m_external)
        return EvpShPtr();

    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    BIO_write(bio.get(), m_binary.data(), m_binary.size());

    switch(m_type)
    {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_ECDSA_PRIVATE:
            pkey = d2i_PrivateKey_bio(bio.get(), NULL);
            break;
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_ECDSA_PUBLIC:
            pkey = d2i_PUBKEY_bio(bio.get(), NULL);
            break;
        default:
            break;
    }
    if (!pkey) {
        LogError("Failed to parse key from key binary");
        return EvpShPtr();
    }

    EvpShPtr ptr(pkey, EVP_PKEY_free);
    return ptr;
}

RawBuffer AsymKeyImpl::toBinary(const KeyType& type, EVP_PKEY* pkey) {
    switch(EVP_PKEY_type(pkey->type))
    {
        case EVP_PKEY_RSA:
            if (type != KeyType::KEY_RSA_PRIVATE && type != KeyType::KEY_RSA_PUBLIC)
                return RawBuffer();
            break;
        case EVP_PKEY_DSA:
            if (type != KeyType::KEY_DSA_PRIVATE && type != KeyType::KEY_DSA_PUBLIC)
                return RawBuffer();
            break;
        case EVP_PKEY_EC:
            if (type != KeyType::KEY_ECDSA_PRIVATE && type != KeyType::KEY_ECDSA_PUBLIC)
                return RawBuffer();
            break;
    }
    switch(type)
    {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_ECDSA_PRIVATE:
            return i2d(i2d_PrivateKey_bio, pkey);

        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_ECDSA_PUBLIC:
            return i2d(i2d_PUBKEY_bio, pkey);

        default:
            break;
    }
    return RawBuffer();
}


//=============================================
// Implementations of SymKeyImpl
//=============================================

SymKeyImpl::SymKeyImpl()
  : KeyImpl()
{}

SymKeyImpl::SymKeyImpl(const SymKeyImpl &second)
  : KeyImpl(second)
{}

SymKeyImpl::SymKeyImpl(const KeyType& type, const RawBuffer& binary, const bool& isExternalKey)
  : KeyImpl(type, binary, isExternalKey)
{}

SymKeyImpl::SymKeyImpl(const KeyType& type, const RawBuffer& binary)
  : KeyImpl(type, binary, false)
{}


//=============================================
// Implementations of KeyBuilder
//=============================================
KeyImplShPtr KeyBuilder::create(const KeyType& type, const RawBuffer &binary, const bool& isExternalKey) {
    try {
        KeyImplShPtr keyImplShPtr;

        AsymKeyImplShPtr asymKeyImplShPtr;
        SymKeyImplShPtr symKeyImplShPtr;

        switch(type)
        {
            case KeyType::KEY_RSA_PRIVATE:
            case KeyType::KEY_DSA_PRIVATE:
            case KeyType::KEY_ECDSA_PRIVATE:
            case KeyType::KEY_RSA_PUBLIC:
            case KeyType::KEY_DSA_PUBLIC:
            case KeyType::KEY_ECDSA_PUBLIC:
                asymKeyImplShPtr = std::make_shared<AsymKeyImpl>(type, binary, isExternalKey);
                keyImplShPtr = asymKeyImplShPtr;
                break;
            case KeyType::KEY_AES:
                symKeyImplShPtr = std::make_shared<SymKeyImpl>(type, binary, isExternalKey);
                keyImplShPtr = symKeyImplShPtr;
                break;
            default:
                break;
        }
        if(keyImplShPtr.get() !=NULL && keyImplShPtr->empty()){
            LogWarning("KeyImpl Creation Failed from internal binary. It may be a wrong internal binary.");
            keyImplShPtr.reset();
        }
        return keyImplShPtr;
    } catch (const std::bad_alloc &) {
         LogDebug("Bad alloc was catch during AsymKeyImpl creation");
    } catch (...) {
         LogError("Critical error: Unknown exception was caught during AsymKeyImpl creation");
    }

    return KeyImplShPtr();
}


KeyImplShPtr KeyBuilder::create(const KeyType &type,
                     const RawBuffer &binary,
                     const Password &password) {
    try {
        KeyImplShPtr keyImplShPtr;

        AsymKeyImplShPtr asymKeyImplShPtr;
        SymKeyImplShPtr symKeyImplShPtr;
        switch(type)
        {
            case KeyType::KEY_RSA_PRIVATE:
            case KeyType::KEY_DSA_PRIVATE:
            case KeyType::KEY_ECDSA_PRIVATE:
            case KeyType::KEY_RSA_PUBLIC:
            case KeyType::KEY_DSA_PUBLIC:
            case KeyType::KEY_ECDSA_PUBLIC:
            case KeyType::KEY_NONE:
                asymKeyImplShPtr = std::make_shared<AsymKeyImpl>(binary, password);
                keyImplShPtr = asymKeyImplShPtr;
                break;
            case KeyType::KEY_AES:
                symKeyImplShPtr = std::make_shared<SymKeyImpl>(type, binary);
                keyImplShPtr = symKeyImplShPtr;
                break;
            default:
                break;
        }
        if(keyImplShPtr.get() !=NULL && keyImplShPtr->empty()){
            LogWarning("KeyImpl Creation Failed from binary. It may be a wrong binary.");
            keyImplShPtr.reset();
        }
        return keyImplShPtr;
    } catch (const std::bad_alloc &) {
         LogDebug("Bad alloc was catch during AsymKeyImpl creation");
    } catch (...) {
         LogError("Critical error: Unknown exception was caught during AsymKeyImpl creation");
    }

    return KeyImplShPtr();
}

AsymKeyImplShPtr KeyBuilder::create(const EvpShPtr &pkey, const KeyType &type) {
    AsymKeyImplShPtr asymKeyImplShPtr = std::make_shared<AsymKeyImpl>(pkey,type);
    if(asymKeyImplShPtr.get() != NULL && asymKeyImplShPtr->empty())
        asymKeyImplShPtr.reset();
    return asymKeyImplShPtr;
}

AsymKeyImplShPtr KeyBuilder::createNullAsymKey()
{
    return std::make_shared<AsymKeyImpl>();
}

SymKeyImplShPtr KeyBuilder::createNullSymKey()
{
    return std::make_shared<SymKeyImpl>();
}

KeyImplShPtr KeyBuilder::toKeyImplShPtr(const KeyShPtr& keyShPtr)
{
    KeyImplShPtr keyImplShPtr;
    try {
        if(keyShPtr.get()  == NULL)
           return KeyImplShPtr();
        keyImplShPtr = create(keyShPtr->getType(), keyShPtr->getBinary(), Password());
    }catch(...) {
        LogWarning("KeyImplShPtr Creation Failed from KeyShPtr. It may be a wrong KeyShPtr.");
    }
    if(keyImplShPtr.get()!= NULL && keyImplShPtr->empty())
        keyImplShPtr.reset();
    return keyImplShPtr;
}

void KeyBuilder::toExternalKey(KeyImplShPtr& pInternalKey, const std::string& externalId)
{
    pInternalKey->setExternalKey(true);
    pInternalKey->setBinary(RawBuffer(externalId.begin(), externalId.end()));    
}

void KeyBuilder::toInternalKey(KeyImplShPtr& pExternalKey, const RawBuffer& binary)
{
    pExternalKey->setExternalKey(false);
    pExternalKey->setBinary(binary);    
}

//=============================================
// Implementations of Key::create
//=============================================
KeyShPtr Key::create(const KeyType type,
                     const RawBuffer &binary,
                     const Password &password) {
    return std::dynamic_pointer_cast<Key>(KeyBuilder::create(type, binary, password));
}


}
