/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by Central Key Manager.
 */

#include <protocols.h>

#include <dpl/serialization.h>

namespace CKM {

char const * const SERVICE_SOCKET_ECHO = "/tmp/.central-key-manager-echo.sock";
char const * const SERVICE_SOCKET_CKM_CONTROL = "/tmp/.central-key-manager-api-control.sock";
char const * const SERVICE_SOCKET_CKM_STORAGE = "/tmp/.central-key-manager-api-storage.sock";
char const * const SERVICE_SOCKET_OCSP = "/tmp/.central-key-manager-api-ocsp.sock";
char const * const LABEL_NAME_SEPARATOR = " ";

DBDataType toDBDataType(KeyType key) {
    switch(key) {
    case KeyType::KEY_RSA_PUBLIC:  return DBDataType::KEY_RSA_PUBLIC;
    case KeyType::KEY_RSA_PRIVATE: return DBDataType::KEY_RSA_PRIVATE;
    case KeyType::KEY_DSA_PUBLIC:  return DBDataType::KEY_DSA_PUBLIC;
    case KeyType::KEY_DSA_PRIVATE: return DBDataType::KEY_DSA_PRIVATE;
    case KeyType::KEY_ECDSA_PUBLIC: return DBDataType::KEY_ECDSA_PUBLIC;
    case KeyType::KEY_ECDSA_PRIVATE: return DBDataType::KEY_ECDSA_PRIVATE;
    case KeyType::KEY_AES: return DBDataType::KEY_AES;
    default:
        // TODO
        throw 1;
    }
}

KeyType toKeyType(DBDataType dbtype) {
    switch(dbtype) {
    case DBDataType::KEY_RSA_PUBLIC: return KeyType::KEY_RSA_PUBLIC;
    case DBDataType::KEY_RSA_PRIVATE: return KeyType::KEY_RSA_PRIVATE;
    case DBDataType::KEY_DSA_PUBLIC: return KeyType::KEY_DSA_PUBLIC;
    case DBDataType::KEY_DSA_PRIVATE: return KeyType::KEY_DSA_PRIVATE;
    case DBDataType::KEY_ECDSA_PRIVATE: return KeyType::KEY_ECDSA_PRIVATE;
    case DBDataType::KEY_ECDSA_PUBLIC: return KeyType::KEY_ECDSA_PUBLIC;
    case DBDataType::KEY_AES: return KeyType::KEY_AES;
    default:
        // TODO
        throw 1;
    }
}

const char* toDBAccessRight(AccessRight access_right_type) {
    switch(access_right_type) {
    case AccessRight::AR_READ:          return "R";
    case AccessRight::AR_READ_REMOVE:   return "RD";
    default:
        // TODO
        throw 1;
    }
}

PolicySerializable::PolicySerializable()
{}


PolicySerializable::PolicySerializable(const Policy &policy)
  : Policy(policy)
{}

PolicySerializable::PolicySerializable(IStream &stream) {
    Deserialization::Deserialize(stream, password);
    Deserialization::Deserialize(stream, extractable);
}

void PolicySerializable::Serialize(IStream &stream) const {
    Serialization::Serialize(stream, password);
    Serialization::Serialize(stream, extractable);
}

} // namespace CKM

