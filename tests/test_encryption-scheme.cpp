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

BOOST_AUTO_TEST_SUITE(ENCRYPTION_SCHEME_TEST)

// Test database should have the old scheme
BOOST_AUTO_TEST_CASE(T010_Check_old_scheme) {
    SchemeTest test;
    test.RestoreDb();
    test.CheckSchemeVersion(false);
}

// Newly written data should use the new scheme
BOOST_AUTO_TEST_CASE(T020_Check_new_scheme) {
    SchemeTest test;
    test.RemoveUserData();
    test.SwitchToUser();
    test.FillDb();
    test.SwitchToRoot();
    test.CheckSchemeVersion(true);
}

// Reading data from old db should reencrypt it with new scheme
BOOST_AUTO_TEST_CASE(T100_Read_to_reencrypt) {
    SchemeTest test;
    test.RestoreDb();
    test.SwitchToUser();
    test.ReadAll();
    test.SwitchToRoot();
    test.CheckSchemeVersion(true);
}

BOOST_AUTO_TEST_SUITE_END()
