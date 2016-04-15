/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       test_for-each-file.cpp
 * @author     Kyungwook Tak (k.tak@samsung.com)
 * @version    1.0
 */
#include <for-each-file.h>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include <vector>
#include <string>

using namespace CKM;

BOOST_AUTO_TEST_SUITE(TRAVERSE_DIR_TEST)

BOOST_AUTO_TEST_CASE(T010_check_prefix)
{
    std::vector<std::string> files;

    forEachFile(DB_TEST_DIR "/traverse", [&files](const std::string & filename) {
        if (filename.find("res-") == std::string::npos)
            return;

        files.push_back(filename);
    });

    BOOST_REQUIRE_MESSAGE(files.size() == 10,
                          "files num in traverse dir should be 10");
}

BOOST_AUTO_TEST_SUITE_END()
