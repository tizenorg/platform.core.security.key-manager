/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-logic.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#pragma once

#include <string>
#include <vector>

#include <message-buffer.h>
#include <protocols.h>
#include <ckm/ckm-type.h>
#include <connection-info.h>
#include <db-crypto.h>
#include <key-provider.h>
#include <crypto-logic.h>
#include <certificate-store.h>

namespace CKM {

struct UserData {
    KeyProvider    keyProvider;
    DBCrypto       database;
    CryptoLogic    crypto;
};

class CKMLogic {
public:
    class Exception
    {
        public:
            DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
            DECLARE_EXCEPTION_TYPE(Base, InputDataInvalid);
    };

    CKMLogic();
    CKMLogic(const CKMLogic &) = delete;
    CKMLogic(CKMLogic &&) = delete;
    CKMLogic& operator=(const CKMLogic &) = delete;
    CKMLogic& operator=(CKMLogic &&) = delete;
    virtual ~CKMLogic();

    RawBuffer unlockUserKey(uid_t user, const Password &password);

    RawBuffer lockUserKey(uid_t user);

    RawBuffer removeUserData(uid_t user);

    RawBuffer changeUserPassword(
        uid_t user,
        const Password &oldPassword,
        const Password &newPassword);

    RawBuffer resetUserPassword(
        uid_t user,
        const Password &newPassword);

    RawBuffer removeApplicationData(const Label &smackLabel);

    RawBuffer saveData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Name &name,
        const RawBuffer &key,
        const PolicySerializable &policy);

    RawBuffer removeData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Name &name,
        const Label &label);

    RawBuffer getData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Name &name,
        const Label &label,
        const Password &password);

    RawBuffer getDataList(
        Credentials &cred,
        int commandId,
        DBDataType dataType);

    RawBuffer createKeyPair(
        Credentials &cred,
        LogicCommand protocol_cmd,
        int commandId,
        const int additional_param,
        const Name &namePrivate,
        const Name &namePublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    RawBuffer getCertificateChain(
        Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const RawBufferVector &untrustedCertificates);

    RawBuffer getCertificateChain(
        Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const AliasVector &aliasVector);

    RawBuffer  createSignature(
        Credentials &cred,
        int commandId,
        const Name &privateKeyName,
        const Label & ownerLabel,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    RawBuffer verifySignature(
        Credentials &cred,
        int commandId,
        const Name &publicKeyOrCertName,
        const Label & ownerLabel,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    RawBuffer updateCCMode();

    RawBuffer allowAccess(
        Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &accessor_label,
        const AccessRight req_rights);

    RawBuffer denyAccess(
        Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &accessor_label);

private:

    void verifyBinaryData(
        DBDataType dataType,
        const RawBuffer &input_data) const;

    int saveDataHelper(
        Credentials &cred,
        DBDataType dataType,
        const Name &name,
        const RawBuffer &key,
        const PolicySerializable &policy);

    int getDataHelper(
        Credentials &cred,
        DBDataType dataType,
        const Name &name,
        const Label &label,
        const Password &password,
        DBRow &row);

    int createKeyPairHelper(
        Credentials &cred,
        const KeyType key_type,
        const int additional_param,
        const Name &namePrivate,
        const Name &namePublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    int getKeyHelper(
        Credentials &cred,
        const Name &publicKeyOrCertName,
        const Password &password,           // password for public_key (optional)
        const KeyImpl &genericKey);


    // @return true if name & label are proper, false otherwise
    static bool checkNameAndLabelValid(
        const Name &name,
        const Label &label);
    void updateCCMode_internal();

    std::map<uid_t, UserData> m_userDataMap;
    CertificateStore m_certStore;
    bool m_ccMode;
};

} // namespace CKM

