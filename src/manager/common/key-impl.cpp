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

int passcb(char *buff, int size, int rwflag, void *userdata)
{
    (void) rwflag;
    Password *ptr = static_cast<Password*>(userdata);

    if (!ptr
        || ptr->empty()
        || ptr->size() > static_cast<size_t>(size)) {
        return 0;
    }

    memcpy(buff, ptr->c_str(), ptr->size());
    return ptr->size();
}

typedef int(*I2D_CONV)(BIO*, EVP_PKEY*);

RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey)
{
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (!pkey) {
        LogDebug("You are trying to read empty key!");
        return RawBuffer();
    }

    if (!bio) {
        LogError("Error in memory allocation! Function: BIO_new.");
        return RawBuffer();
    }

    if (1 != fun(bio.get(), pkey)) {
        LogError("Error in conversion EVP_PKEY to der");
        return RawBuffer();
    }

    RawBuffer output(8196);

    int size = BIO_read(bio.get(), output.data(), output.size());

    if (size <= 0) {
        LogError("Error in BIO_read: " << size);
        return RawBuffer();
    }

    output.resize(size);
    return output;
}

bool isAsym(const KeyType type)
{
    switch (type) {
    case KeyType::KEY_RSA_PRIVATE:
    case KeyType::KEY_DSA_PRIVATE:
    case KeyType::KEY_ECDSA_PRIVATE:
    case KeyType::KEY_RSA_PUBLIC:
    case KeyType::KEY_DSA_PUBLIC:
    case KeyType::KEY_ECDSA_PUBLIC:
        return true;
    case KeyType::KEY_AES:
    default:
        return false;
    }
}

bool isPrivate(const KeyType type)
{
    switch (type) {
    case KeyType::KEY_RSA_PRIVATE:
    case KeyType::KEY_ECDSA_PRIVATE:
    case KeyType::KEY_DSA_PRIVATE:
        return true;
    case KeyType::KEY_RSA_PUBLIC:
    case KeyType::KEY_ECDSA_PUBLIC:
    case KeyType::KEY_DSA_PUBLIC:
    case KeyType::KEY_AES:
    default:
        return false;
    }
}

bool isValidType(const KeyType type,
                 const bool isPrivate,
                 const int pkeyType)
{
    switch (pkeyType) {
    case EVP_PKEY_RSA:
        if ((isPrivate && type == KeyType::KEY_RSA_PRIVATE)
            || (!isPrivate && type == KeyType::KEY_RSA_PUBLIC))
            return true;
    case EVP_PKEY_DSA:
        if ((isPrivate && type == KeyType::KEY_DSA_PRIVATE)
            || (!isPrivate && type == KeyType::KEY_DSA_PUBLIC))
            return true;
    case EVP_PKEY_EC:
        if ((isPrivate && type == KeyType::KEY_ECDSA_PRIVATE)
            || (!isPrivate && type == KeyType::KEY_ECDSA_PUBLIC))
            return true;
    default:
        break;
    }

    return false;
}

KeyType getValidType(int pkeyType, int isPrivate)
{
    switch (pkeyType) {
    case EVP_PKEY_RSA:
        return isPrivate ?
            KeyType::KEY_RSA_PRIVATE
          : KeyType::KEY_RSA_PUBLIC;
    case EVP_PKEY_DSA:
        return isPrivate ?
            KeyType::KEY_DSA_PRIVATE
          : KeyType::KEY_DSA_PUBLIC;
    case EVP_PKEY_EC:
        return isPrivate ?
            KeyType::KEY_ECDSA_PRIVATE
          : KeyType::KEY_ECDSA_PUBLIC;
    default:
        return KeyType::KEY_NONE;
    }
}

} // anonymous namespace


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

void KeyImpl::toExternalKey(const std::string &externalId)
{
    setExternalKey(true);
    setBinary(RawBuffer(externalId.begin(), externalId.end()));
}

void KeyImpl::toInternalKey(const RawBuffer &binary)
{
    setExternalKey(false);
    setBinary(binary);
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
  : KeyImpl()
{
    m_type = type;
    setBinaryWithEvp(pkey.get());
}

AsymKeyImpl::AsymKeyImpl(const RawBuffer &keyBuffer,
                         const Password &password)
  : KeyImpl()
{
    if (keyBuffer.empty()) {
        LogWarning("keyBuffer is empty");
        return;
    }

    bool isPrivate = false;
    EvpShPtr pkey;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    // DER format
    if (keyBuffer[0] != '-') {
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(d2i_PrivateKey_bio(bio.get(), NULL),
                        EVP_PKEY_free);
        isPrivate = true;
    }

    // PEM format
    if (!pkey && keyBuffer[0] == '-') {
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(PEM_read_bio_PrivateKey(bio.get(),
                                                NULL,
                                                passcb,
                                                const_cast<Password*>(&password)),
                        EVP_PKEY_free);
        isPrivate = true;
    }

    // DER format
    if (!pkey && keyBuffer[0] != '-') {
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(d2i_PUBKEY_bio(bio.get(), NULL),
                        EVP_PKEY_free);
        isPrivate = false;
    }

    if (!pkey && keyBuffer[0] == '-') {
        BIO_write(bio.get(), keyBuffer.data(), keyBuffer.size());
        pkey = EvpShPtr(PEM_read_bio_PUBKEY(bio.get(),
                                            NULL,
                                            passcb,
                                            const_cast<Password*>(&password)),
                        EVP_PKEY_free);
        isPrivate = false;
    }

    if (!pkey) {
        LogError("Failed to parse key");
        return;
    }

    m_type = getValidType(EVP_PKEY_type(pkey->type), isPrivate);

    if (m_type == KeyType::KEY_NONE) {
        LogError("Invalid key type");
        return;
    }

    setBinaryWithEvp(pkey.get());

    LogDebug("KeyType is: " << static_cast<int>(m_type)
        << " isPrivate: " << isPrivate
        << ", size: " << m_binary.size());
}

EvpShPtr AsymKeyImpl::getEvpShPtr() const
{
    if (m_external || !isAsym(m_type))
        return EvpShPtr();

    EvpShPtr pkey;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    BIO_write(bio.get(), m_binary.data(), m_binary.size());

    if (isPrivate(m_type))
        pkey = EvpShPtr(d2i_PrivateKey_bio(bio.get(), NULL), EVP_PKEY_free);
    else
        pkey = EvpShPtr(d2i_PUBKEY_bio(bio.get(), NULL), EVP_PKEY_free);

    if (!pkey) {
        LogError("Failed to parse key from key binary");
        return EvpShPtr();
    }

    return pkey;
}

void AsymKeyImpl::setBinaryWithEvp(EVP_PKEY *pkey)
{
    if (!isAsym(m_type)) {
        LogError("Invalid key type");
        return;
    }

    if (!isValidType(m_type, isPrivate(m_type), EVP_PKEY_type(pkey->type))) {
        LogError("pkey and keyType doesn't match");
        return;
    }

    if (isPrivate(m_type))
        setBinary(i2d(i2d_PrivateKey_bio, pkey));
    else
        setBinary(i2d(i2d_PUBKEY_bio, pkey));
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
{
    // TODO: change return to throw
    if (isAsym(type)) {
        LogError("Invalid key type");
        return;
    }
}

//=============================================
// Implementations of Key::create
//=============================================
KeyShPtr Key::create(const RawBuffer &keyBuffer,
                     const KeyType type,
                     const Password &password)
{
    try {
        KeyShPtr keyShPtr;

        // For case of key type unspecified. let's try asym key first
        if (type == KeyType::KEY_NONE) {
            keyShPtr = std::make_shared<AsymKeyImpl>(keyBuffer, password);
            if (keyShPtr->empty())
                keyShPtr = std::make_shared<SymKeyImpl>(keyBuffer, type);
        }
        else {
            if (isAsym(type))
                keyShPtr = std::make_shared<AsymKeyImpl>(keyBuffer, password);
            else
                keyShPtr = std::make_shared<SymKeyImpl>(keyBuffer, type);
        }


        if (keyShPtr->empty()) {
            LogWarning("KeyImpl Creation Failed from internal binary. "
                       "It may be a wrong internal binary.");
            keyShPtr.reset();
        }

        return keyShPtr;
    } catch (const std::bad_alloc &) {
         LogError("Bad alloc was catch during AsymKeyImpl creation");
    } catch (...) {
         LogError("Critical error: Unknown exception was caught "
                  "during AsymKeyImpl creation");
    }

    return KeyShPtr();
}

}
