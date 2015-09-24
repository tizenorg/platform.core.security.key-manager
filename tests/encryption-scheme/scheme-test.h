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
 * @file       scheme-test.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <memory>
#include <string>

#include <ckm/ckm-control.h>
#include <ckm/ckm-manager.h>

#include <data-type.h>

namespace CKM {
namespace DB {
class Crypto;
}
}

struct Item {
    const CKM::Alias alias;
    const CKM::DataType::Type type;
    const CKM::Policy& policy;
};

class SchemeTest {
public:
    SchemeTest();
    ~SchemeTest();

    void RemoveUserData();
    void SwitchToUser();
    void SwitchToRoot();
    void FillDb();
    void ReadAll();
    void RestoreDb();
    void CheckSchemeVersion(bool isNew);


private:
    void EnableDirectDbAccess();
    void CheckKeyExportability(const Item& item);
    void CheckCertExportability(const Item& item);
    void CheckPkcs(const Item& item);
    void ReadData(const Item& item);
    void SignVerify(const Item& itemPrv, const Item& itemPub);
    void EncryptDecrypt(const Item& item);
    void CreateCertChain(const CKM::CertificateShPtr& leaf, const Item& ca, const Item& root);

    CKM::ControlShPtr m_control;
    CKM::ManagerShPtr m_mgr;
    std::string m_origLabel;
    bool m_userChanged;

    std::unique_ptr<CKM::DB::Crypto> m_db;
    bool m_directAccessEnabled;
};
