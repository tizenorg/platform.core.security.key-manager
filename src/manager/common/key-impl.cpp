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
  : m_binary(RawBuffer())
{
    m_type     = KeyType::KEY_NONE;
    m_format   = KeyFormat::KFORM_NONE;
    m_bin_size = 0;
}

KeyImpl::KeyImpl(const KeyType type, const KeyFormat format, const RawBuffer& binary)
  : m_type(type)
  , m_format(format)
  , m_binary(RawBuffer())
{
    setBinary(binary);
}

KeyImpl::KeyImpl(const KeyImpl &second)
  : m_binary(RawBuffer())
{
    m_type     = second.m_type;
    m_format   = second.m_format;
    m_bin_size = second.m_bin_size;
    m_binary.assign( second.m_binary.begin(), second.m_binary.end() );
}

KeyImpl::KeyImpl(const RawBuffer &internalBinary)
  : m_binary(RawBuffer())
{
    setInternalBinary(internalBinary);
}


bool KeyImpl::empty() const {
    return m_binary.empty();
}

KeyType KeyImpl::getType() const {
    return m_type;
}

void KeyImpl::setType(const KeyType type) {
    m_type = type;
	return;
}

RawBuffer KeyImpl::getBinary() const {
    return m_binary;
}

void KeyImpl::setBinary(const RawBuffer& binary) {
    m_bin_size = binary.size();
    m_binary.clear();
    m_binary.assign(binary.begin(), binary.end());
    return;
}

KeyFormat KeyImpl::getFormat() const {
    return m_format;
}

void KeyImpl::setFormat(const KeyFormat format) {
    m_format = format;
	return;
}

RawBuffer KeyImpl::getInternalBinary() const {
    RawBuffer outBuffer;
	outBuffer.clear();
    outBuffer.push_back(static_cast<unsigned int>(m_type));
    outBuffer.push_back(static_cast<unsigned int>(m_format));
    outBuffer.push_back(static_cast<unsigned int>(m_bin_size));
    outBuffer.insert(outBuffer.begin()+3, m_binary.begin(), m_binary.end());
    return outBuffer;
}

void KeyImpl::setInternalBinary(const RawBuffer& internalBinary) {
    m_type     = static_cast<KeyType>(static_cast<int>(internalBinary.at(0)));
    m_format   = static_cast<KeyFormat>(static_cast<int>(internalBinary.at(1)));
    m_bin_size = static_cast<int>(internalBinary.at(2));
    m_binary.clear();
    m_binary.assign( internalBinary.begin()+3,  internalBinary.end() );
}

void KeyImpl::setKeyImpl(const KeyImplShPtr keyImplShPtr) {
    setType(keyImplShPtr->getType());
    setFormat(keyImplShPtr->getFormat());
    setBinary(keyImplShPtr->getBinary());
}

//=============================================
// Implementations of AsymKeyImpl
//=============================================

AsymKeyImpl::AsymKeyImpl()
  : KeyImpl()
  , m_pkey(NULL, EVP_PKEY_free)
{}

AsymKeyImpl::AsymKeyImpl(const AsymKeyImpl &second)
  : KeyImpl(second)
  , m_pkey(NULL, EVP_PKEY_free)
{
    binaryToEvpShPtr();
}

AsymKeyImpl::AsymKeyImpl(const RawBuffer& internalBinary)
  : KeyImpl(internalBinary)
  , m_pkey(NULL, EVP_PKEY_free)
{
    binaryToEvpShPtr();
}

AsymKeyImpl::AsymKeyImpl(const RawBuffer& binary, const Password &password)
  : KeyImpl()
{
    setBinary(binary);
    setFormat(KeyFormat::KFORM_DER);
    binaryToEvpShPtr(password);
    setBinary(getDER()); // reset binary again because the previous binary may be in the PEM format.
}

AsymKeyImpl::AsymKeyImpl(const EvpShPtr &pkey, const KeyType &type)
  : KeyImpl(type, KeyFormat::KFORM_DER, RawBuffer())
  , m_pkey(NULL, EVP_PKEY_free)
{
    m_pkey = pkey;
    setBinary(getDER());
}

void AsymKeyImpl::setKeyImpl(const KeyImplShPtr keyImplShPtr) {
    setType(keyImplShPtr->getType());
    setFormat(keyImplShPtr->getFormat());
    setBinary(keyImplShPtr->getBinary());
    AsymKeyImpl *pKeyImpl = dynamic_cast<AsymKeyImpl *>(keyImplShPtr.get());
    m_pkey = pKeyImpl->getEvpShPtr();
}

void AsymKeyImpl::binaryToEvpShPtr(const Password &password) {
    bool isPrivate = false;
    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    LogDebug("Start to parse key:");
    if(m_binary.size() == 0) {
        LogWarning("Fail to convert binary to EVP_PKEY. binary size is 0.");
        return;
    }
//    printDER(m_binary);

    if (m_binary[0] != '-') {
        BIO_write(bio.get(), m_binary.data(), m_binary.size());
        pkey = d2i_PUBKEY_bio(bio.get(), NULL);
        isPrivate = false;
        LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
    }

    if (!pkey && m_binary[0] != '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_binary.data(), m_binary.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        isPrivate = true;
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey && m_binary[0] == '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_binary.data(), m_binary.size());
        pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = false;
        LogDebug("PEM_read_bio_PUBKEY Status: " << (void*)pkey);
    }

    if (!pkey && m_binary[0] == '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_binary.data(), m_binary.size());
        pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = true;
        LogDebug("PEM_read_bio_PrivateKey Status: " << (void*)pkey);
    }

    if (!pkey) {
        LogError("Failed to parse key");
        m_binary.clear();
        return;
    }

    m_pkey.reset(pkey, EVP_PKEY_free);

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
    LogDebug("KeyType is: " << (int)m_type << " isPrivate: " << isPrivate);
}

RawBuffer AsymKeyImpl::getDER() const {
    switch(m_type)
    {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_ECDSA_PRIVATE:
            return getDERPRV();

        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_ECDSA_PUBLIC:
            return getDERPUB();

        default:
            break;
    }
    return RawBuffer();
}


RawBuffer AsymKeyImpl::getDERPRV() const {
    return i2d(i2d_PrivateKey_bio, m_pkey.get());
}

RawBuffer AsymKeyImpl::getDERPUB() const {
    return i2d(i2d_PUBKEY_bio, m_pkey.get());
}

EvpShPtr AsymKeyImpl::getEvpShPtr() const {
    return m_pkey;
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

SymKeyImpl::SymKeyImpl(const RawBuffer& internalBinary)
  : KeyImpl(internalBinary)
{}

SymKeyImpl::SymKeyImpl(const RawBuffer& binary, const KeyType type)
  : KeyImpl()
{
    setType(type);
    setBinary(binary);
    setFormat(KeyFormat::KFORM_RAW);
}

int SymKeyImpl::getSize() const {
	return m_bin_size;
}


//=============================================
// Implementations of KeyBuilder
//=============================================
KeyImplShPtr KeyBuilder::create(const RawBuffer &internalBinary) {
    try {
        KeyImplShPtr keyImplShPtr;

        if(internalBinary.size() <= 3) {
            LogWarning("KeyImpl Creation Failed from internal binary. It may be a wrong internal binary.");
            return KeyImplShPtr();
        }

        KeyType type = KeyType::KEY_NONE;
        type = static_cast<KeyType>(static_cast<int>(internalBinary.at(0)));
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
                asymKeyImplShPtr = std::make_shared<AsymKeyImpl>(internalBinary);
                keyImplShPtr = std::dynamic_pointer_cast<KeyImpl>(asymKeyImplShPtr);
                break;
            case KeyType::KEY_AES:
                symKeyImplShPtr = std::make_shared<SymKeyImpl>(internalBinary);
                keyImplShPtr = std::dynamic_pointer_cast<KeyImpl>(symKeyImplShPtr);
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

KeyImplShPtr KeyBuilder::create(const EvpShPtr &pkey, const KeyType &type) {
    AsymKeyImplShPtr asymKeyImplShPtr = std::make_shared<AsymKeyImpl>(pkey,type);
    if(asymKeyImplShPtr.get() != NULL && asymKeyImplShPtr->empty())
        asymKeyImplShPtr.reset();
    return std::dynamic_pointer_cast<KeyImpl>(asymKeyImplShPtr);
}

KeyImplShPtr KeyBuilder::create(const KeyType type,
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
                keyImplShPtr = std::dynamic_pointer_cast<KeyImpl>(asymKeyImplShPtr);
                break;
            case KeyType::KEY_AES:
                symKeyImplShPtr = std::make_shared<SymKeyImpl>(binary, type);
                keyImplShPtr = std::dynamic_pointer_cast<KeyImpl>(symKeyImplShPtr);
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

KeyImplShPtr KeyBuilder::createNullAsymKey()
{
    return std::dynamic_pointer_cast<KeyImpl>(std::make_shared<AsymKeyImpl>());
}

KeyImplShPtr KeyBuilder::createNullSymKey()
{
    return std::dynamic_pointer_cast<KeyImpl>(std::make_shared<SymKeyImpl>());
}

KeyImplShPtr KeyBuilder::toKeyImplShPtr(KeyShPtr keyShPtr)
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
//=============================================
// Implementations of Key::create
//=============================================
KeyShPtr Key::create(const KeyType type,
                     const RawBuffer &binary,
                     const Password &password) {
    return std::dynamic_pointer_cast<Key>(KeyBuilder::create(type, binary, password));
}


}
