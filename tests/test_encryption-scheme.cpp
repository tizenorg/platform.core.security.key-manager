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
 * @file       test_encryption-scheme.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include <scheme-test.h>

using namespace CKM;

BOOST_AUTO_TEST_SUITE(ENCRYPTION_SCHEME_TEST)

// Test database should have the old scheme
BOOST_AUTO_TEST_CASE(T010_Check_old_scheme) {
    SchemeTest test;
    test.RestoreDb();

    ItemFilter filter;
    test.CheckSchemeVersion(filter, false);
}

// Newly written data should use the new scheme
BOOST_AUTO_TEST_CASE(T020_Check_new_scheme) {
    SchemeTest test;
    test.RemoveUserData();
    test.SwitchToUser();
    test.FillDb();
    test.SwitchToRoot();

    ItemFilter filter;
    test.CheckSchemeVersion(filter, true);
}

// Reading data from old db should reencrypt it with new scheme
BOOST_AUTO_TEST_CASE(T100_Read_to_reencrypt) {
    SchemeTest test;
    test.RestoreDb();
    test.SwitchToUser();
    test.ReadAll();
    test.SwitchToRoot();

    ItemFilter filter;
    filter.exportableOnly = true;
    test.CheckSchemeVersion(filter, true);
}

BOOST_AUTO_TEST_CASE(T110_SignVerify_to_reencrypt) {
    SchemeTest test;
    test.RestoreDb();
    test.SwitchToUser();
    test.SignVerify();
    test.SwitchToRoot();

    ItemFilter filter(DataType::KEY_RSA_PUBLIC, DataType::KEY_RSA_PRIVATE);
    test.CheckSchemeVersion(filter, true);
}

BOOST_AUTO_TEST_CASE(T120_EncryptDecrypt_to_reencrypt) {
    SchemeTest test;
    test.RestoreDb();
    test.SwitchToUser();
    test.EncryptDecrypt();
    test.SwitchToRoot();

    ItemFilter filter1(DataType::KEY_RSA_PUBLIC, DataType::KEY_RSA_PRIVATE);
    test.CheckSchemeVersion(filter1, true);

    ItemFilter filter2(DataType::KEY_AES);
    test.CheckSchemeVersion(filter2, true);
}

BOOST_AUTO_TEST_CASE(T130_CreateChain_to_reencrypt) {
    SchemeTest test;
    test.RestoreDb();
    test.SwitchToUser();
    test.CreateChain();
    test.SwitchToRoot();

    // non exportable certificates and certificates protected with passwords can't be used for chain
    // creation
    ItemFilter filter1(DataType::CERTIFICATE);
    filter1.exportableOnly = true;
    filter1.noPassword = true;
    test.CheckSchemeVersion(filter1, true);

    ItemFilter filter2(DataType::CHAIN_CERT_0, DataType::CHAIN_CERT_15);
    filter2.exportableOnly = true;
    filter2.noPassword = true;
    test.CheckSchemeVersion(filter2, true);
}

BOOST_AUTO_TEST_SUITE_END()
