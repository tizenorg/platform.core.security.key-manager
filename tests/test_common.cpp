/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Kyungwook Tak <k.tak@samsung.com>
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
 * @file        test_common.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version
 * @brief
 */
#include <test_common.h>
#include <iostream>

using namespace CKM;

RawBuffer createDefaultPass() {
    return createPass(0, RAW_PASS_SIZE);
}

RawBuffer createPass(std::size_t from, std::size_t to) {
    RawBuffer raw;

    for (std::size_t i = from; i < to; i++)
        raw.push_back(static_cast<unsigned char>(i));

    return raw;
}

RawBuffer createBigBlob(std::size_t size) {
    return createPass(0, size);
}

//raw to hex string conversion from SqlConnection
std::string rawToHexString(const RawBuffer &raw) {
    std::string dump;

    for (auto &e : raw) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", (e && 0xff));
        dump.push_back(buf[0]);
        dump.push_back(buf[1]);
    }

    return dump;
}
