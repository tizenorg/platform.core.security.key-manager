/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        certificate-impl.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate implementation.
 */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <dpl/log/log.h>

#include <key-impl.h>
#include <certificate-impl.h>
#include <base64.h>

namespace CKM {

CertificateImpl::CertificateImpl(const RawBuffer &der, DataFormat format)
	: m_x509(nullptr) {
	LogDebug("Certificate to parse. Size: " << der.size());

	if (DataFormat::FORM_DER_BASE64 == format) {
		Base64Decoder base64;
		base64.reset();
		base64.append(der);
		base64.finalize();
		auto tmp = base64.get();
		auto ptr = reinterpret_cast<const unsigned char *>(tmp.data());
		auto size = static_cast<int>(tmp.size());
		m_x509 = d2i_X509(nullptr, &ptr, size);
	} else if (DataFormat::FORM_DER == format) {
		auto ptr = reinterpret_cast<const unsigned char *>(der.data());
		auto size = static_cast<int>(der.size());
		m_x509 = d2i_X509(nullptr, &ptr, size);
	} else if (DataFormat::FORM_PEM == format) {
		auto buff = BIO_new(BIO_s_mem());
		BIO_write(buff, der.data(), der.size());
		m_x509 = PEM_read_bio_X509(buff, nullptr, nullptr, nullptr);
		BIO_free_all(buff);
	} else {
		// TODO
		LogError("Unknown certificate format");
	}

	if (!m_x509) {
		// TODO
		LogError("Certificate could not be parsed.");
		//      ThrowMsg(Exception::OpensslInternalError,
		//         "Internal Openssl error in d2i_X509 function.");
	}
}

CertificateImpl::CertificateImpl(X509 *x509, bool duplicate) {
	if (duplicate)
		m_x509 = X509_dup(x509);
	else
		m_x509 = x509;
}

CertificateImpl::CertificateImpl(CertificateImpl &&second) {
	m_x509 = second.m_x509;
	second.m_x509 = nullptr;
	LogDebug("Certificate moved: " << (void *)m_x509);
}

CertificateImpl &CertificateImpl::operator=(CertificateImpl &&second) {
	if (this == &second)
		return *this;

	if (m_x509)
		X509_free(m_x509);

	m_x509 = second.m_x509;
	second.m_x509 = nullptr;
	LogDebug("Certificate moved: " << (void *)m_x509);
	return *this;
}

X509 *CertificateImpl::getX509() const {
	return m_x509;
}

RawBuffer CertificateImpl::getDER(void) const {
	unsigned char *rawDer = nullptr;
	int size = i2d_X509(m_x509, &rawDer);

	if (!rawDer || size <= 0) {
		LogError("i2d_X509 failed");
		return RawBuffer();
	}

	RawBuffer output(
		reinterpret_cast<char *>(rawDer),
		reinterpret_cast<char *>(rawDer) + size);
	OPENSSL_free(rawDer);
	return output;
}

bool CertificateImpl::empty() const {
	return m_x509 == nullptr;
}

KeyImpl::EvpShPtr CertificateImpl::getEvpShPtr() const {
	return KeyImpl::EvpShPtr(X509_get_pubkey(m_x509), EVP_PKEY_free);
}

std::string CertificateImpl::getOCSPURL() const {
	if (!m_x509)
		return std::string();

	STACK_OF(OPENSSL_STRING) *aia = X509_get1_ocsp(m_x509);

	if (nullptr == aia)
		return std::string();

	std::string result(sk_OPENSSL_STRING_value(aia, 0));
	X509_email_free(aia);   // TODO is it correct?
	return result;
}

CertificateImpl::~CertificateImpl() {
	if (m_x509)
		X509_free(m_x509);
}

CertificateShPtr Certificate::create(const RawBuffer &rawBuffer, DataFormat format) {
	try {
		CertificateShPtr output = std::make_shared<CertificateImpl>(rawBuffer, format);

		if (output->empty())
			output.reset();

		return output;
	} catch (const std::bad_alloc &) {
		LogDebug("Bad alloc was caught during CertificateImpl creation");
	} catch (...) {
		LogError("Critical error: Unknown exception was caught during CertificateImpl creation!");
	}

	return CertificateShPtr();
}

} // namespace CKM

