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

namespace {
typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

int passcb(char *buff, int size, int rwflag, void *userdata)
{
    (void) rwflag;
    CKM::Password *ptr = static_cast<CKM::Password*>(userdata);

    if (!ptr
        || ptr->empty()
        || ptr->size() > static_cast<size_t>(size)) {
        return 0;
    }

    memcpy(buff, ptr->c_str(), ptr->size());
    return ptr->size();
}

typedef int(*I2D_CONV)(BIO*, EVP_PKEY*);

CKM::RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey)
{
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (!pkey) {
        LogDebug("You are trying to read empty key!");
        return CKM::RawBuffer();
    }

    if (!bio) {
        LogError("Error in memory allocation! Function: BIO_new.");
        return CKM::RawBuffer();
    }

    if (1 != fun(bio.get(), pkey)) {
        LogError("Error in conversion EVP_PKEY to der");
        return CKM::RawBuffer();
    }

    CKM::RawBuffer output(8196);

    int size = BIO_read(bio.get(), output.data(), output.size());

    if (size <= 0) {
        LogError("Error in BIO_read: " << size);
        return CKM::RawBuffer();
    }

    output.resize(size);
    return output;
}

bool isSymmetric(const CKM::KeyType type)
{
    switch (type) {
        case CKM::KeyType::KEY_AES:
            return true;
        case CKM::KeyType::KEY_RSA_PRIVATE:
        case CKM::KeyType::KEY_DSA_PRIVATE:
        case CKM::KeyType::KEY_ECDSA_PRIVATE:
        case CKM::KeyType::KEY_RSA_PUBLIC:
        case CKM::KeyType::KEY_DSA_PUBLIC:
        case CKM::KeyType::KEY_ECDSA_PUBLIC:
        default:
            return false;
    }
}

} // anonymous namespace


namespace CKM {

//=============================================
// Implementations of KeyImpl
//=============================================

KeyImpl::KeyImpl()
  : m_type(KeyType::KEY_NONE)
  , m_external(false)
{}

KeyImpl::KeyImpl(const RawBuffer &keyBuffer,
                 const KeyType type,
                 const bool isExternalKey)
  : m_type(type)
  , m_external(isExternalKey)
{
    setBinary(keyBuffer);
}

KeyImpl::KeyImpl(const KeyImpl &second)
  : m_type(second.m_type)
  , m_external(second.m_external)
{
    setBinary(second.getBinary());
}

bool KeyImpl::empty() const
{
    return m_binary.empty();
}

KeyType KeyImpl::getType() const
{
    return m_type;
}

RawBuffer KeyImpl::getBinary() const
{
    return m_binary;
}

bool KeyImpl::isExternalKey() const
{
    return m_external;
}

void KeyImpl::setType(const KeyType type)
{
    m_type = type;
}

void KeyImpl::setBinary(const RawBuffer &binary)
{
    m_binary.assign(binary.begin(), binary.end());
}

void KeyImpl::setExternalKey(const bool isExternalKey)
{
    m_external = isExternalKey;
}

void KeyImpl::toExternalKey(KeyImpl &pInternalKey, const std::string &externalId)
{
    pInternalKey.setExternalKey(true);
    pInternalKey.setBinary(RawBuffer(externalId.begin(), externalId.end()));
}

void KeyImpl::toInternalKey(KeyImpl &pExternalKey, const RawBuffer &binary)
{
    pExternalKey.setExternalKey(false);
    pExternalKey.setBinary(binary);
}


//=============================================
// Implementations of AsymKeyImpl
//=============================================
AsymKeyImpl::AsymKeyImpl()
  : KeyImpl()
{}

AsymKeyImpl::AsymKeyImpl(const RawBuffer &keyBuffer,
                         const KeyType type,
                         const bool isExternalKey)
  : KeyImpl(keyBuffer, type, isExternalKey)
{}

AsymKeyImpl::AsymKeyImpl(EvpShPtr pkey, const KeyType type)
  : KeyImpl(RawBuffer(), type)
{
    setBinary(pkey.get(), type);
}

AsymKeyImpl::AsymKeyImpl(const RawBuffer& keyBuffer, const Password &password)
  : KeyImpl()
{
    bool isPrivate = false;
    EvpShPtr pkey;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (keyBuffer.empty()) {
        LogWarning("keyBuffer is empty");
        return;
    }

    // try pubkey with DER
    if (keyBuffer[0] != '-') {
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(d2i_PUBKEY_bio(bio.get(), NULL), EVP_PKEY_free);
        isPrivate = false;
    }

    // try prikey with DER
    if (!pkey && keyBuffer[0] != '-') {
        BIO_reset(bio.get());
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(d2i_PrivateKey_bio(bio.get(), NULL), EVP_PKEY_free);
        isPrivate = true;
    }

    // try pubkey with PEM
    if (!pkey && keyBuffer[0] == '-') {
        BIO_reset(bio.get());
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(PEM_read_bio_PUBKEY(bio.get(),
                                            NULL,
                                            passcb,
                                            const_cast<Password*>(&password)),
                        EVP_PKEY_free);
        isPrivate = false;
    }

    // try prikey with PEM
    if (!pkey && keyBuffer[0] == '-') {
        BIO_reset(bio.get());
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(PEM_read_bio_PrivateKey(bio.get(),
                                                NULL,
                                                passcb,
                                                const_cast<Password*>(&password)),
                        EVP_PKEY_free);
        isPrivate = true;
    }

    if (!pkey) {
        LogError("Failed to parse key");
        return;
    }

    // set Type
    switch (EVP_PKEY_type(pkey->type))
    {
        case EVP_PKEY_RSA:
            m_type = isPrivate ?
                    KeyType::KEY_RSA_PRIVATE : KeyType::KEY_RSA_PUBLIC;
            break;

        case EVP_PKEY_DSA:
            m_type = isPrivate ?
                    KeyType::KEY_DSA_PRIVATE : KeyType::KEY_DSA_PUBLIC;
            break;

        case EVP_PKEY_EC:
            m_type = isPrivate ?
                    KeyType::KEY_ECDSA_PRIVATE : KeyType::KEY_ECDSA_PUBLIC;
            break;
    }

    setBinary(pkey.get(), m_type);

    LogDebug("KeyType is: " << static_cast<int>(m_type)
        << " isPrivate: " << isPrivate
        << ", size: " << m_binary.size());
}

EvpShPtr AsymKeyImpl::getEvpShPtr() const
{
    if (m_external)
        return EvpShPtr();

    EvpShPtr pkey;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    BIO_write(bio.get(), m_binary.data(), m_binary.size());

    switch (m_type)
    {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_ECDSA_PRIVATE:
            pkey = EvpShPtr(d2i_PrivateKey_bio(bio.get(), NULL), EVP_PKEY_free);
            break;
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_ECDSA_PUBLIC:
            pkey = EvpShPtr(d2i_PUBKEY_bio(bio.get(), NULL), EVP_PKEY_free);
            break;
        default:
            break;
    }

    if (!pkey) {
        LogError("Failed to parse key from key binary");
        return EvpShPtr();
    }

    return pkey;
}

void AsymKeyImpl::setBinary(EVP_PKEY *pkey, const KeyType type)
{
    switch (EVP_PKEY_type(pkey->type))
    {
        case EVP_PKEY_RSA:
            if (type != KeyType::KEY_RSA_PRIVATE
                && type != KeyType::KEY_RSA_PUBLIC) {
                LogError("pkey and keyType doesn't match");
                return;
            }
            break;
        case EVP_PKEY_DSA:
            if (type != KeyType::KEY_DSA_PRIVATE
                && type != KeyType::KEY_DSA_PUBLIC) {
                LogError("pkey and keyType doesn't match");
                return;
            }
            break;
        case EVP_PKEY_EC:
            if (type != KeyType::KEY_ECDSA_PRIVATE
                && type != KeyType::KEY_ECDSA_PUBLIC) {
                LogError("pkey and keyType doesn't match");
                return;
            }
            break;
    }

    switch (type)
    {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_ECDSA_PRIVATE:
            KeyImpl::setBinary(i2d(i2d_PrivateKey_bio, pkey));
            break;
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_ECDSA_PUBLIC:
            KeyImpl::setBinary(i2d(i2d_PUBKEY_bio, pkey));
            break;
        default:
            LogError("Invalid key type");
            break;
    }
}


//=============================================
// Implementations of SymKeyImpl
//=============================================
SymKeyImpl::SymKeyImpl()
  : KeyImpl()
{}

SymKeyImpl::SymKeyImpl(const RawBuffer &keyBuffer,
                       const KeyType type,
                       const bool isExternalKey)
  : KeyImpl(keyBuffer, type, isExternalKey)
{}


//=============================================
// Implementations of KeyBuilder
//=============================================

KeyImplShPtr KeyBuilder::create(const RawBuffer &keyBuffer,
                                const KeyType type,
                                const bool isExternalKey)
{
    KeyImplShPtr keyImplShPtr;

    try {
        keyImplShPtr = std::make_shared<KeyImpl>(keyBuffer, type, isExternalKey);

        if (keyImplShPtr && keyImplShPtr->empty()) {
            LogWarning("KeyImpl Creation Failed from internal binary. "
                       "It may be a wrong internal binary.");
            keyImplShPtr.reset();
        }

        return keyImplShPtr;
    } catch (const std::bad_alloc &) {
         LogError("Bad alloc was catch during AsymKeyImpl creation");
    } catch (...) {
         LogError("Critical error: Unknown exception was caught "
                  "during AsymKeyImpl creation");
    }

    return KeyImplShPtr();
}

KeyImplShPtr KeyBuilder::createUnparsedKey(const RawBuffer &keyBuffer,
                                           const KeyType type,
                                           const Password &password)
{
    KeyImplShPtr keyImplShPtr;

    try {
        if (isSymmetric(type))
            keyImplShPtr = std::make_shared<KeyImpl>(keyBuffer, type);
        else
            keyImplShPtr = std::make_shared<AsymKeyImpl>(keyBuffer, password);

        if (keyImplShPtr && keyImplShPtr->empty()) {
            LogWarning("KeyImpl Creation Failed from internal binary. "
                       "It may be a wrong internal binary.");
            keyImplShPtr.reset();
        }

        return keyImplShPtr;
    } catch (const std::bad_alloc &) {
         LogError("Bad alloc was catch during AsymKeyImpl creation");
    } catch (...) {
         LogError("Critical error: Unknown exception was caught "
                  "during AsymKeyImpl creation");
    }

    return KeyImplShPtr();
}

AsymKeyImplShPtr KeyBuilder::create(EvpShPtr pkey, const KeyType type)
{
    AsymKeyImplShPtr asymKeyImplShPtr = std::make_shared<AsymKeyImpl>(pkey, type);

    if (asymKeyImplShPtr && asymKeyImplShPtr->empty())
        asymKeyImplShPtr.reset();
    return asymKeyImplShPtr;
}


//=============================================
// Implementations of Key::create
//=============================================
KeyShPtr Key::create(const RawBuffer &binary,
                     const KeyType type,
                     const Password &password)
{
    return KeyBuilder::createUnparsedKey(binary, type, password);
}

}
