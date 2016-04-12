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
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by Central Key Manager.
 */
#include "protocols.h"

#include <utility>

#include <dpl/serialization.h>
#include <dpl/log/log.h>
#include <ckm/ckm-type.h>

namespace CKM {

char const *const SERVICE_SOCKET_ECHO = "/tmp/.central-key-manager-echo.sock";
char const *const SERVICE_SOCKET_CKM_CONTROL =
	"/tmp/.central-key-manager-api-control.sock";
char const *const SERVICE_SOCKET_CKM_STORAGE =
	"/tmp/.central-key-manager-api-storage.sock";
char const *const SERVICE_SOCKET_OCSP =
	"/tmp/.central-key-manager-api-ocsp.sock";
char const *const SERVICE_SOCKET_ENCRYPTION =
	"/tmp/.central-key-manager-api-encryption.sock";
char const *const LABEL_NAME_SEPARATOR = " ";
char const *const OWNER_ID_SYSTEM = "/System";

PKCS12Serializable::PKCS12Serializable()
{
}

PKCS12Serializable::PKCS12Serializable(const PKCS12 &pkcs)
	: PKCS12Impl(pkcs)
{
}

PKCS12Serializable::PKCS12Serializable(PKCS12Serializable &&other)
	: PKCS12Impl(std::move(other))
{
}

PKCS12Serializable &PKCS12Serializable::operator=(PKCS12Serializable &&other)
{
	if (this == &other)
		return *this;

	m_pkey = std::move(other.m_pkey);
	m_cert = std::move(other.m_cert);
	m_ca = std::move(other.m_ca);

	return *this;
}

PKCS12Serializable::PKCS12Serializable(IStream &stream)
{
	bool keyPresent = false;
	Deserialization::Deserialize(stream, keyPresent);

	if (keyPresent) {
		int keyType;
		RawBuffer keyData;
		Deserialization::Deserialize(stream, keyType);
		Deserialization::Deserialize(stream, keyData);
		m_pkey = CKM::Key::create(keyData);

		if (m_pkey)
			LogDebug("private key from pkcs deserialized success. key size: " <<
					 keyData.size() << " and DER size: " << m_pkey->getDER().size());
		else
			LogError("private key from pkcs deserialized fail");
	}

	bool certPresent = false;
	Deserialization::Deserialize(stream, certPresent);

	if (certPresent) {
		RawBuffer certData;
		Deserialization::Deserialize(stream, certData);
		m_cert = CKM::Certificate::create(certData, DataFormat::FORM_DER);

		if (m_cert)
			LogDebug("certificate from pkcs deserialized success. cert size: " <<
					 certData.size() << " and DER size: " << m_cert->getDER().size());
		else
			LogError("certificate from pkcs deserialized fail");
	}

	size_t numCA = 0;
	Deserialization::Deserialize(stream, numCA);

	for (size_t i = 0; i < numCA; i++) {
		RawBuffer CAcertData;
		Deserialization::Deserialize(stream, CAcertData);
		m_ca.emplace_back(CKM::Certificate::create(CAcertData, DataFormat::FORM_DER));

		if (m_pkey)
			LogDebug("ca certificate from pkcs deserialized success. cert size: " <<
					 CAcertData.size() << " and DER size: " << CKM::Certificate::create(CAcertData,
							 DataFormat::FORM_DER)->getDER().size());
		else
			LogError("ca certificate from pkcs deserialized fail");
	}
}

PKCS12Serializable::PKCS12Serializable(KeyShPtr &&privKey,
									   CertificateShPtr &&cert, CertificateShPtrVector &&chainCerts)
{
	m_pkey = std::move(privKey);
	m_cert = std::move(cert);
	m_ca = std::move(chainCerts);
}

void PKCS12Serializable::Serialize(IStream &stream) const
{
	auto keyPtr = getKey();
	bool isKeyPresent = !!keyPtr;

	// logics if PKCS is correct or not is on the service side.
	// sending number of keys and certificates to allow proper parsing on the service side.
	// (what if no key or cert present? attempt to deserialize a not present key/cert would
	// throw an error and close the connection).
	Serialization::Serialize(stream, isKeyPresent);

	if (isKeyPresent) {
		Serialization::Serialize(stream, DataType(keyPtr->getType()));
		Serialization::Serialize(stream, keyPtr->getDER());
		LogDebug("private key from pkcs serialized success. key DER size: " <<
				 keyPtr->getDER().size());
	}

	auto certPtr = getCertificate();
	bool isCertPresent = !!certPtr;
	Serialization::Serialize(stream, isCertPresent);

	if (isCertPresent) {
		Serialization::Serialize(stream, certPtr->getDER());
		LogDebug("certificate from pkcs serialized success. cert DER size: " <<
				 certPtr->getDER().size());
	}

	auto caCertPtrVec = getCaCertificateShPtrVector();
	Serialization::Serialize(stream, caCertPtrVec.size());

	for (auto &caCertPtr : getCaCertificateShPtrVector()) {
		Serialization::Serialize(stream, caCertPtr->getDER());
		LogDebug("ca certificate from pkcs serialized success. cert DER size: " <<
				 caCertPtr->getDER().size());
	}
};


CryptoAlgorithmSerializable::CryptoAlgorithmSerializable()
{
}

CryptoAlgorithmSerializable::CryptoAlgorithmSerializable(
	const CryptoAlgorithm &algo) :
	CryptoAlgorithm(algo)
{
}

CryptoAlgorithmSerializable::CryptoAlgorithmSerializable(IStream &stream)
{
	size_t plen = 0;
	Deserializer<size_t>::Deserialize(stream, plen);

	while (plen) {
		ParamName name;
		uint64_t integer;
		RawBuffer buffer;
		int tmpName;
		Deserializer<int>::Deserialize(stream, tmpName);
		name = static_cast<ParamName>(tmpName);

		switch (name) {
		case ParamName::ED_IV:
		case ParamName::ED_AAD:
		case ParamName::ED_LABEL:
			Deserializer<RawBuffer>::Deserialize(stream, buffer);
			setParam(name, buffer);
			break;

		case ParamName::ALGO_TYPE:
		case ParamName::ED_CTR_LEN:
		case ParamName::ED_TAG_LEN:
		case ParamName::GEN_KEY_LEN:
		case ParamName::GEN_EC:
		case ParamName::SV_HASH_ALGO:
		case ParamName::SV_RSA_PADDING:
			Deserializer<uint64_t>::Deserialize(stream, integer);
			setParam(name, integer);
			break;

		default:
			ThrowMsg(UnsupportedParam, "Unsupported param name");
		}

		plen--;
	}
}

void CryptoAlgorithmSerializable::Serialize(IStream &stream) const
{
	Serializer<size_t>::Serialize(stream, m_params.size());

	for (const auto &it : m_params) {
		Serializer<int>::Serialize(stream, static_cast<int>(it.first));
		uint64_t integer;
		RawBuffer buffer;

		if (it.second->getInt(integer))
			Serializer<uint64_t>::Serialize(stream, integer);
		else if (it.second->getBuffer(buffer))
			Serializer<RawBuffer>::Serialize(stream, buffer);
		else
			ThrowMsg(UnsupportedParam, "Unsupported param type");
	}
}

} // namespace CKM

