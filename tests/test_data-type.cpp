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
 * @file        test_data-type.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       DataType class test
 */
#include <data-type.h>

#include <boost/test/unit_test.hpp>

#include <ckm/ckm-type.h>

using CKM::DataType;
using CKM::KeyType;
using CKM::AlgoType;

BOOST_AUTO_TEST_SUITE(DATA_TYPE_TEST)

BOOST_AUTO_TEST_CASE(CONSTRUCTOR)
{
	BOOST_REQUIRE_THROW(DataType(static_cast<DataType::Type>(999)),
						DataType::Exception::OutOfRange);
	BOOST_REQUIRE_THROW(DataType(static_cast<KeyType>(999)),
						DataType::Exception::OutOfRange);

	std::vector<DataType> types;

	types.emplace_back(AlgoType::AES_CTR);
	types.emplace_back(AlgoType::AES_CBC);
	types.emplace_back(AlgoType::AES_GCM);
	types.emplace_back(AlgoType::AES_CFB);
	types.emplace_back(AlgoType::AES_GEN);

	for (auto &type : types)
		BOOST_REQUIRE(type == DataType(DataType::KEY_AES));

	types.clear();

	types.emplace_back(AlgoType::RSA_SV);
	types.emplace_back(AlgoType::RSA_OAEP);
	types.emplace_back(AlgoType::RSA_GEN);

	for (auto &type : types)
		BOOST_REQUIRE(type == DataType(DataType::KEY_RSA_PUBLIC));

	types.clear();

	types.emplace_back(AlgoType::DSA_SV);
	types.emplace_back(AlgoType::DSA_GEN);

	for (auto &type : types)
		BOOST_REQUIRE(type == DataType(DataType::KEY_DSA_PUBLIC));

	types.clear();

	types.emplace_back(AlgoType::ECDSA_SV);
	types.emplace_back(AlgoType::ECDSA_GEN);

	for (auto &type : types)
		BOOST_REQUIRE(type == DataType(DataType::KEY_ECDSA_PUBLIC));

	types.clear();

	BOOST_REQUIRE_THROW(
		DataType(static_cast<AlgoType>(-1)),
		DataType::Exception::OutOfRange);
}

BOOST_AUTO_TEST_CASE(KEY_TYPE_CASTING)
{
	std::vector<std::pair<DataType, KeyType>> pairs;

	pairs.emplace_back(DataType::KEY_RSA_PUBLIC, KeyType::KEY_RSA_PUBLIC);
	pairs.emplace_back(DataType::KEY_RSA_PRIVATE, KeyType::KEY_RSA_PRIVATE);

	pairs.emplace_back(DataType::KEY_DSA_PUBLIC, KeyType::KEY_DSA_PUBLIC);
	pairs.emplace_back(DataType::KEY_DSA_PRIVATE, KeyType::KEY_DSA_PRIVATE);

	pairs.emplace_back(DataType::KEY_ECDSA_PUBLIC, KeyType::KEY_ECDSA_PUBLIC);
	pairs.emplace_back(DataType::KEY_ECDSA_PRIVATE, KeyType::KEY_ECDSA_PRIVATE);

	pairs.emplace_back(DataType::KEY_AES, KeyType::KEY_AES);

	for (auto &p : pairs)
		BOOST_REQUIRE(p.second == DataType(static_cast<KeyType>(p.first)));
}

BOOST_AUTO_TEST_CASE(UNARY_OPERATIONS)
{
	BOOST_REQUIRE(DataType(DataType::KEY_AES).isSKey());
	BOOST_REQUIRE(!DataType(DataType::KEY_RSA_PUBLIC).isSKey());

	BOOST_REQUIRE(DataType(DataType::DB_CHAIN_FIRST).isChainCert());
	BOOST_REQUIRE(DataType(DataType::DB_CHAIN_LAST).isChainCert());
	BOOST_REQUIRE(!DataType(DataType::KEY_AES).isChainCert());

	BOOST_REQUIRE(DataType(DataType::KEY_RSA_PUBLIC).isKeyPublic());
	BOOST_REQUIRE(DataType(DataType::KEY_DSA_PUBLIC).isKeyPublic());
	BOOST_REQUIRE(DataType(DataType::KEY_ECDSA_PUBLIC).isKeyPublic());
	BOOST_REQUIRE(!DataType(DataType::KEY_RSA_PRIVATE).isKeyPublic());
	BOOST_REQUIRE(!DataType(DataType::KEY_DSA_PRIVATE).isKeyPublic());
	BOOST_REQUIRE(!DataType(DataType::KEY_ECDSA_PRIVATE).isKeyPublic());
	BOOST_REQUIRE(!DataType(DataType::KEY_AES).isKeyPublic());
	BOOST_REQUIRE(!DataType(DataType::DB_CHAIN_LAST).isKeyPublic());

	BOOST_REQUIRE(DataType(DataType::KEY_RSA_PRIVATE).isKeyPrivate());
	BOOST_REQUIRE(DataType(DataType::KEY_DSA_PRIVATE).isKeyPrivate());
	BOOST_REQUIRE(DataType(DataType::KEY_ECDSA_PRIVATE).isKeyPrivate());
	BOOST_REQUIRE(!DataType(DataType::KEY_RSA_PUBLIC).isKeyPrivate());
	BOOST_REQUIRE(!DataType(DataType::KEY_DSA_PUBLIC).isKeyPrivate());
	BOOST_REQUIRE(!DataType(DataType::KEY_ECDSA_PUBLIC).isKeyPrivate());
	BOOST_REQUIRE(!DataType(DataType::KEY_AES).isKeyPrivate());
	BOOST_REQUIRE(!DataType(DataType::DB_CHAIN_FIRST).isKeyPrivate());

	BOOST_REQUIRE(DataType(DataType::CERTIFICATE).isCertificate());
	BOOST_REQUIRE(!DataType(DataType::KEY_AES).isCertificate());
	BOOST_REQUIRE(!DataType().isCertificate());
	BOOST_REQUIRE(!DataType(DataType::DB_CHAIN_FIRST).isCertificate());

	BOOST_REQUIRE(DataType().isBinaryData());
	BOOST_REQUIRE(DataType(DataType::BINARY_DATA).isBinaryData());
	BOOST_REQUIRE(!DataType(DataType::KEY_AES).isBinaryData());
	BOOST_REQUIRE(!DataType(DataType::KEY_RSA_PUBLIC).isBinaryData());
	BOOST_REQUIRE(!DataType(DataType::DB_CHAIN_LAST).isBinaryData());

	BOOST_REQUIRE(DataType(DataType::DB_KEY_FIRST).isKey());
	BOOST_REQUIRE(DataType(DataType::DB_KEY_LAST).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_AES).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_RSA_PUBLIC).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_RSA_PRIVATE).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_DSA_PUBLIC).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_DSA_PRIVATE).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_ECDSA_PUBLIC).isKey());
	BOOST_REQUIRE(DataType(DataType::KEY_ECDSA_PRIVATE).isKey());
	BOOST_REQUIRE(!DataType(DataType::DB_CHAIN_FIRST).isKey());
	BOOST_REQUIRE(!DataType(DataType::CERTIFICATE).isKey());
	BOOST_REQUIRE(!DataType().isKey());
}

BOOST_AUTO_TEST_CASE(GET_CHAIN_TYPE)
{
	DataType type;

	BOOST_REQUIRE(type.getChainDatatype(0) == DataType(DataType::DB_CHAIN_FIRST));
	BOOST_REQUIRE(type.getChainDatatype(5) == DataType(DataType::CHAIN_CERT_5));
	BOOST_REQUIRE(type.getChainDatatype(8) == DataType(DataType::CHAIN_CERT_8));
	BOOST_REQUIRE(type.getChainDatatype(13) == DataType(DataType::CHAIN_CERT_13));
	BOOST_REQUIRE(type.getChainDatatype(15) == DataType(DataType::DB_CHAIN_LAST));

	BOOST_REQUIRE_THROW(type.getChainDatatype(16), DataType::Exception::OutOfRange);
}

BOOST_AUTO_TEST_SUITE_END()
