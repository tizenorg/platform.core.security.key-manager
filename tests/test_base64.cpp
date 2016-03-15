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
 *
 * @file        test_base64.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       base64 encoder / decoder test
 */
#include <base64.h>

#include <vector>
#include <cstring>
#include <boost/test/unit_test.hpp>

#include <ckm/ckm-type.h>

using CKM::Base64Encoder;
using CKM::Base64Decoder;
using CKM::RawBuffer;

namespace {

constexpr unsigned char RAW_DATA[] =  {
    0xf8, 0x87, 0x0a, 0xc5, 0xd3, 0x6d, 0x44, 0x49, 0x03, 0x9f, 0xbd, 0x1e, 0xa8, 0x2f, 0xf6, 0xc3,
    0xdf, 0x3b, 0x02, 0x13, 0x58, 0x1b, 0x12, 0x30, 0x1c, 0xd7, 0xad, 0xa5, 0x1f, 0x5d, 0x01, 0x33
};

const std::vector<unsigned char>
    RAW_DATA_VEC(RAW_DATA, RAW_DATA + sizeof(RAW_DATA) / sizeof(unsigned char));

const RawBuffer rawbuf(RAW_DATA_VEC.begin(), RAW_DATA_VEC.end());

}

BOOST_AUTO_TEST_SUITE(BASE64_TEST)

BOOST_AUTO_TEST_CASE(ENCODE_DECODE_POSITIVE)
{
    /* try encode */
    Base64Encoder encoder;
    BOOST_REQUIRE_NO_THROW(encoder.append(rawbuf));
    BOOST_REQUIRE_NO_THROW(encoder.finalize());

    RawBuffer encdata;
    BOOST_REQUIRE_NO_THROW(encdata = encoder.get());
    BOOST_REQUIRE_NO_THROW(encoder.reset());

    /* try decode */
    Base64Decoder decoder;
    BOOST_REQUIRE_NO_THROW(decoder.append(encdata));
    BOOST_REQUIRE_NO_THROW(decoder.finalize());

    RawBuffer decdata;
    BOOST_REQUIRE_NO_THROW(decdata = decoder.get());
    BOOST_REQUIRE_NO_THROW(decoder.reset());
    
    /* compare with orig data */
    BOOST_REQUIRE_MESSAGE(
        rawbuf.size() == decdata.size() && memcmp(rawbuf.data(), decdata.data(), rawbuf.size()) == 0,
        "Original data and encoded-decoded data is different!");
}

BOOST_AUTO_TEST_CASE(THROW_SOMETHING)
{
    /* encode data */
    Base64Encoder encoder;
    BOOST_REQUIRE_THROW(encoder.get(), Base64Encoder::Exception::NotFinalized);

    BOOST_REQUIRE_NO_THROW(encoder.append(rawbuf));
    BOOST_REQUIRE_NO_THROW(encoder.finalize());

    BOOST_REQUIRE_THROW(encoder.append(rawbuf), Base64Encoder::Exception::AlreadyFinalized);
    BOOST_REQUIRE_THROW(encoder.finalize(), Base64Encoder::Exception::AlreadyFinalized);

    RawBuffer encdata;
    BOOST_REQUIRE_NO_THROW(encdata = encoder.get());

    /* decode data */
    Base64Decoder decoder;
    BOOST_REQUIRE_THROW(decoder.get(), Base64Decoder::Exception::NotFinalized);

    BOOST_REQUIRE_NO_THROW(decoder.append(encdata));
    BOOST_REQUIRE_NO_THROW(decoder.finalize());

    BOOST_REQUIRE_THROW(decoder.append(encdata), Base64Decoder::Exception::AlreadyFinalized);
    BOOST_REQUIRE_THROW(decoder.finalize(), Base64Decoder::Exception::AlreadyFinalized);

    RawBuffer decdata;
    BOOST_REQUIRE_NO_THROW(decdata = decoder.get());
}

BOOST_AUTO_TEST_CASE(ILLEGAL_DATA)
{
    Base64Decoder decoder;
    BOOST_REQUIRE_NO_THROW(decoder.append(rawbuf));
    BOOST_REQUIRE(!decoder.finalize());
}

BOOST_AUTO_TEST_SUITE_END()
