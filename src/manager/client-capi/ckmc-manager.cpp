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
 * @file        ckmc-control.h
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       provides conversion methods to C from C++ for key-manager control functions.
 */

#include <dpl/log/log.h>
#include <ckm/ckm-type.h>
#include <ckm/ckm-manager.h>
#include <ckmc/ckmc-type.h>
#include <ckmc/ckmc-manager.h>
#include <ckmc/ckmc-error.h>
#include <ckmc-type-converter.h>
#include <client-common.h>
#include <iostream>
#include <string.h>

namespace {
const CKM::CertificateShPtrVector EMPTY_CERT_VECTOR;
const CKM::AliasVector EMPTY_ALIAS_VECTOR;

inline CKM::Password _tostring(const char *str) {
	return (str == nullptr) ? CKM::Password() : CKM::Password(str);
}

inline CKM::Policy _toCkmPolicy(const ckmc_policy_s &policy) {
	return CKM::Policy(_tostring(policy.password), policy.extractable);
}

inline CKM::KeyShPtr _toCkmKey(const ckmc_key_s *key) {
	return (key == nullptr) ?
		   CKM::KeyShPtr() :
		   CKM::Key::create(
			   CKM::RawBuffer(key->raw_key, key->raw_key + key->key_size),
			   _tostring(key->password));
}

inline CKM::CertificateShPtr _toCkmCertificate(const ckmc_cert_s *cert) {
	return (cert == nullptr) ?
		   CKM::CertificateShPtr() :
		   CKM::Certificate::create(
			   CKM::RawBuffer(cert->raw_cert, cert->raw_cert + cert->cert_size),
			   static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format)));
}

CKM::CertificateShPtrVector _toCkmCertificateVector(const ckmc_cert_list_s *list) {
	CKM::CertificateShPtrVector certs;
	auto current = list;

	while (current != nullptr) {
		if (current->cert != nullptr)
			certs.emplace_back(_toCkmCertificate(current->cert));

		current = current->next;
	}

	return certs;
}

CKM::AliasVector _toCkmAliasVector(const ckmc_alias_list_s *list) {
	CKM::AliasVector aliases;
	auto current = list;

	while (current != nullptr) {
		if (current->alias != nullptr)
			aliases.emplace_back(CKM::Alias(current->alias));

		current = current->next;
	}

	return aliases;
}

ckmc_cert_list_s *_toNewCkmCertList(const CKM::CertificateShPtrVector &certVector) {
	ckmc_cert_list_s *start = nullptr;
	ckmc_cert_list_s *plist = nullptr;

	for (const auto &e : certVector) {
		auto rawBuffer = e->getDER();
		ckmc_cert_s *pcert = nullptr;
		int ret = ckmc_cert_new(rawBuffer.data(), rawBuffer.size(), CKMC_FORM_DER, &pcert);

		if (ret != CKMC_ERROR_NONE || pcert == nullptr) {
			ckmc_cert_list_all_free(start);
			return nullptr;
		}

		ret = ckmc_cert_list_add(plist, pcert, &plist);

		if (ret != CKMC_ERROR_NONE) {
			ckmc_cert_list_all_free(start);
			return nullptr;
		}

		if (start == nullptr)
			start = plist;
	}

	return start;
}

typedef int (CKM::Manager::*cryptoFn)(const CKM::CryptoAlgorithm &,
									  const CKM::Alias &,
									  const CKM::Password &,
									  const CKM::RawBuffer &,
									  CKM::RawBuffer &);

int _cryptoOperation(cryptoFn operation,
					 ckmc_param_list_h params,
					 const char *key_alias,
					 const char *password,
					 const ckmc_raw_buffer_s in,
					 ckmc_raw_buffer_s **ppout) {
	if (!params || !key_alias || !ppout)
		return CKMC_ERROR_INVALID_PARAMETER;

	// params
	const CKM::CryptoAlgorithm *ca = reinterpret_cast<const CKM::CryptoAlgorithm *>(params);
	// password
	CKM::Password pass;

	if (password)
		pass = password;

	// buffers
	CKM::RawBuffer inBuffer(in.data, in.data + in.size);
	CKM::RawBuffer outBuffer;
	auto mgr = CKM::Manager::create();
	int ret = ((*mgr).*operation)(*ca, key_alias, pass, inBuffer, outBuffer);

	if (ret != CKM_API_SUCCESS)
		return to_ckmc_error(ret);

	return ckmc_buffer_new(outBuffer.data(), outBuffer.size(), ppout);
}

int try_catch_enclosure(const std::function<int()> &func) {
	try {
		return func();
	} catch (const std::bad_alloc &e) {
		LogError("memory allocation exception: " << e.what());
		return CKMC_ERROR_OUT_OF_MEMORY;
	} catch (const std::exception &e) {
		LogError("std exception occured: " << e.what());
		return CKMC_ERROR_UNKNOWN;
	} catch (...) {
		LogError("Unknown exception occured.");
		return CKMC_ERROR_UNKNOWN;
	}
}

}

KEY_MANAGER_CAPI
int ckmc_save_key(const char *alias, const ckmc_key_s key, const ckmc_policy_s policy) {
	return try_catch_enclosure([&]()->int {
		auto mgr = CKM::Manager::create();

		if (alias == nullptr || key.raw_key == nullptr || key.key_size == 0)
			return CKMC_ERROR_INVALID_PARAMETER;

		CKM::RawBuffer buffer(key.raw_key, key.raw_key + key.key_size);
		CKM::KeyShPtr ckmKey;

		if (key.key_type == CKMC_KEY_AES) {
			if (key.password)
				return CKMC_ERROR_INVALID_PARAMETER;

			ckmKey = CKM::Key::createAES(buffer);
		} else
			ckmKey = CKM::Key::create(buffer, _tostring(key.password));

		if (!ckmKey)
			return CKMC_ERROR_INVALID_FORMAT;

		return to_ckmc_error(mgr->saveKey(CKM::Alias(alias), ckmKey, _toCkmPolicy(policy)));
	});
}


KEY_MANAGER_CAPI
int ckmc_remove_key(const char *alias) {
	return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_key(const char *alias, const char *password, ckmc_key_s **key) {
	return try_catch_enclosure([&]()->int {
		if (alias == nullptr || key == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		int ret;
		CKM::KeyShPtr ckmKey;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->getKey(alias, _tostring(password), ckmKey)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		auto buffer = ckmKey->getDER();
		return ckmc_key_new(
			buffer.data(),
			buffer.size(),
			static_cast<ckmc_key_type_e>(static_cast<int>(ckmKey->getType())),
			nullptr,
			key);
	});
}

KEY_MANAGER_CAPI
int ckmc_get_key_alias_list(ckmc_alias_list_s **alias_list) {
	return try_catch_enclosure([&]()->int {
		int ret;

		if (alias_list == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		CKM::AliasVector aliasVector;
		auto mgr = CKM::Manager::create();

		if ((ret = mgr->getKeyAliasVector(aliasVector)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		ckmc_alias_list_s *start = nullptr;
		ckmc_alias_list_s *plist = nullptr;

		for (const auto &it : aliasVector) {
			char *alias = strndup(it.c_str(), it.size());
			ret = ckmc_alias_list_add(plist, alias, &plist);

			if (ret != CKMC_ERROR_NONE) {
				free(alias);
				ckmc_alias_list_all_free(start);
				return ret;
			}

			if (start == nullptr)
				start = plist;
		}

		if (plist == nullptr) // if the alias_list size is zero
			return CKMC_ERROR_DB_ALIAS_UNKNOWN;

		*alias_list = start;

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_save_cert(const char *alias, const ckmc_cert_s cert, const ckmc_policy_s policy) {
	return try_catch_enclosure([&]()->int {
		if (alias == nullptr || cert.raw_cert == nullptr || cert.cert_size == 0)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto ckmCert = _toCkmCertificate(&cert);
		if (!ckmCert)
			return CKMC_ERROR_INVALID_FORMAT;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->saveCertificate(CKM::Alias(alias), ckmCert, _toCkmPolicy(policy)));
	});
}

KEY_MANAGER_CAPI
int ckmc_remove_cert(const char *alias) {
	return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_cert(const char *alias, const char *password, ckmc_cert_s **cert) {
	return try_catch_enclosure([&]()->int {
		CKM::CertificateShPtr ckmCert;
		int ret;

		if (alias == nullptr || cert == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		if ((ret = mgr->getCertificate(alias, _tostring(password), ckmCert)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		auto buffer = ckmCert->getDER();
		return ckmc_cert_new(buffer.data(), buffer.size(), CKMC_FORM_DER, cert);
	});
}

KEY_MANAGER_CAPI
int ckmc_get_cert_alias_list(ckmc_alias_list_s **alias_list) {
	return try_catch_enclosure([&]()->int {
		if (alias_list == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		CKM::AliasVector aliasVector;
		int ret;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->getCertificateAliasVector(aliasVector)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		ckmc_alias_list_s *start = nullptr;
		ckmc_alias_list_s *plist = nullptr;

		for (const auto &it : aliasVector) {
			char *alias = strndup(it.c_str(), it.size());
			ret = ckmc_alias_list_add(plist, alias, &plist);

			if (ret != CKMC_ERROR_NONE) {
				free(alias);
				ckmc_alias_list_all_free(start);
				return ret;
			}

			if (start == nullptr)
				start = plist;
		}

		if (plist == nullptr) // if the alias_list size is zero
			return CKMC_ERROR_DB_ALIAS_UNKNOWN;

		*alias_list = start;

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_save_pkcs12(const char *alias, const ckmc_pkcs12_s *ppkcs, const ckmc_policy_s key_policy,
					 const ckmc_policy_s cert_policy) {
	return try_catch_enclosure([&]()->int {
		if (alias == nullptr || ppkcs == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		CKM::PKCS12ShPtr pkcs12(new CKM::PKCS12Impl(
			_toCkmKey(ppkcs->priv_key),
			_toCkmCertificate(ppkcs->cert),
			_toCkmCertificateVector(ppkcs->ca_chain)));

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->savePKCS12(
			CKM::Alias(alias),
			pkcs12,
			_toCkmPolicy(key_policy),
			_toCkmPolicy(cert_policy)));
	});
}

KEY_MANAGER_CAPI
int ckmc_get_pkcs12(const char *alias, const char *key_password, const char *cert_password,
					ckmc_pkcs12_s **pkcs12) {
	return try_catch_enclosure([&]()->int {
		if (!alias || !pkcs12)
			return CKMC_ERROR_INVALID_PARAMETER;

		int ret;
		CKM::PKCS12ShPtr pkcs;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->getPKCS12(alias, _tostring(key_password), _tostring(cert_password), pkcs)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		if (!pkcs)
			return CKMC_ERROR_BAD_RESPONSE;

		ckmc_key_s *private_key = nullptr;
		auto pkcsKey = pkcs->getKey();
		if (pkcsKey) {
			auto buffer = pkcsKey->getDER();
			ckmc_key_type_e keyType = static_cast<ckmc_key_type_e>(pkcsKey->getType());
			ret = ckmc_key_new(buffer.data(), buffer.size(), keyType, nullptr, &private_key);

			if (ret != CKMC_ERROR_NONE)
				return ret;
		}

		ckmc_cert_s *cert = nullptr;
		auto pkcsCert = pkcs->getCertificate();

		if (pkcsCert) {
			CKM::RawBuffer buffer = pkcsCert->getDER();
			ret = ckmc_cert_new(buffer.data(), buffer.size(), CKMC_FORM_DER, &cert);

			if (ret != CKMC_ERROR_NONE) {
				ckmc_key_free(private_key);
				return ret;
			}
		}

		auto ca_cert_list = _toNewCkmCertList(pkcs->getCaCertificateShPtrVector());

		ret = ckmc_pkcs12_new(private_key, cert, ca_cert_list, pkcs12);

		if (ret != CKMC_ERROR_NONE) {
			ckmc_key_free(private_key);
			ckmc_cert_free(cert);
			ckmc_cert_list_free(ca_cert_list);
		}

		return ret;
	});
}


KEY_MANAGER_CAPI
int ckmc_save_data(const char *alias, ckmc_raw_buffer_s data, const ckmc_policy_s policy) {
	return try_catch_enclosure([&]()->int {
		if (alias == nullptr || data.data == nullptr || data.size == 0)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->saveData(
			CKM::Alias(alias),
			CKM::RawBuffer(data.data, data.data + data.size),
			_toCkmPolicy(policy)));
	});
}

KEY_MANAGER_CAPI
int ckmc_remove_data(const char *alias) {
	return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_data(const char *alias, const char *password, ckmc_raw_buffer_s **data) {
	return try_catch_enclosure([&]()->int {
		if (alias == nullptr || data == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		int ret;
		CKM::RawBuffer ckmBuff;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->getData(alias, _tostring(password), ckmBuff)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		return ckmc_buffer_new(ckmBuff.data(), ckmBuff.size(), data);
	});
}

KEY_MANAGER_CAPI
int ckmc_get_data_alias_list(ckmc_alias_list_s **alias_list) {
	return try_catch_enclosure([&]()->int {
		if (alias_list == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		int ret;
		CKM::AliasVector aliasVector;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->getDataAliasVector(aliasVector)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		ckmc_alias_list_s *start = nullptr;
		ckmc_alias_list_s *plist = nullptr;

		for (const auto &it : aliasVector) {
			char *alias = strndup(it.c_str(), it.size());
			ret = ckmc_alias_list_add(plist, alias, &plist);

			if (ret != CKMC_ERROR_NONE) {
				free(alias);
				ckmc_alias_list_all_free(start);
				return ret;
			}

			if (start == nullptr)
				start = plist;
		}

		if (plist == nullptr) // if the alias_list size is zero
			return CKMC_ERROR_DB_ALIAS_UNKNOWN;

		*alias_list = start;

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_rsa(const size_t size,
							 const char *private_key_alias,
							 const char *public_key_alias,
							 const ckmc_policy_s policy_private_key,
							 const ckmc_policy_s policy_public_key) {
	return try_catch_enclosure([&]()->int {
		auto mgr = CKM::Manager::create();

		if (private_key_alias == nullptr || public_key_alias == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		return to_ckmc_error(mgr->createKeyPairRSA(
			static_cast<int>(size),
			CKM::Alias(private_key_alias),
			CKM::Alias(public_key_alias),
			_toCkmPolicy(policy_private_key),
			_toCkmPolicy(policy_public_key)));
	});
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_dsa(const size_t size,
							 const char *private_key_alias,
							 const char *public_key_alias,
							 const ckmc_policy_s policy_private_key,
							 const ckmc_policy_s policy_public_key) {
	return try_catch_enclosure([&]()->int {
		if (private_key_alias == nullptr || public_key_alias == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->createKeyPairDSA(
			static_cast<int>(size),
			CKM::Alias(private_key_alias),
			CKM::Alias(public_key_alias),
			_toCkmPolicy(policy_private_key),
			_toCkmPolicy(policy_public_key)));
	});
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_ecdsa(const ckmc_ec_type_e type,
							   const char *private_key_alias,
							   const char *public_key_alias,
							   const ckmc_policy_s policy_private_key,
							   const ckmc_policy_s policy_public_key) {
	return try_catch_enclosure([&]()->int {
		if (private_key_alias == nullptr || public_key_alias == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->createKeyPairECDSA(
			static_cast<CKM::ElipticCurve>(static_cast<int>(type)),
			CKM::Alias(private_key_alias),
			CKM::Alias(public_key_alias),
			_toCkmPolicy(policy_private_key),
			_toCkmPolicy(policy_public_key)));
	});
}

KEY_MANAGER_CAPI
int ckmc_create_key_aes(size_t size,
						const char *key_alias,
						ckmc_policy_s key_policy) {
	return try_catch_enclosure([&]()->int {
		if (key_alias == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->createKeyAES(size, CKM::Alias(key_alias), _toCkmPolicy(key_policy)));
	});
}

KEY_MANAGER_CAPI
int ckmc_create_signature(const char *private_key_alias,
						  const char *password,
						  const ckmc_raw_buffer_s message,
						  const ckmc_hash_algo_e hash,
						  const ckmc_rsa_padding_algo_e padding,
						  ckmc_raw_buffer_s **signature) {
	return try_catch_enclosure([&]()->int {
		if (private_key_alias == nullptr || signature == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		int ret;
		CKM::RawBuffer ckmSignature;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->createSignature(
			CKM::Alias(private_key_alias),
			_tostring(password),
			CKM::RawBuffer(message.data, message.data + message.size),
			static_cast<CKM::HashAlgorithm>(static_cast<int>(hash)),
			static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding)),
			ckmSignature)) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		return ckmc_buffer_new(ckmSignature.data(), ckmSignature.size(), signature);
	});
}

KEY_MANAGER_CAPI
int ckmc_verify_signature(const char *public_key_alias,
						  const char *password,
						  const ckmc_raw_buffer_s message,
						  const ckmc_raw_buffer_s signature,
						  const ckmc_hash_algo_e hash,
						  const ckmc_rsa_padding_algo_e padding) {
	return try_catch_enclosure([&]()->int {
		if (public_key_alias == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		int ret;
		auto mgr = CKM::Manager::create();
		if ((ret = mgr->verifySignature(
			CKM::Alias(public_key_alias),
			_tostring(password),
			CKM::RawBuffer(message.data, message.data + message.size),
			CKM::RawBuffer(signature.data, signature.data + signature.size),
			static_cast<CKM::HashAlgorithm>(static_cast<int>(hash)),
			static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding)))) != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain(const ckmc_cert_s *cert, const ckmc_cert_list_s *untrustedcerts,
						ckmc_cert_list_s **cert_chain_list) {
	return try_catch_enclosure([&]()->int {
		if (cert == nullptr || cert->raw_cert == nullptr || cert->cert_size == 0 || cert_chain_list == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto ckmCert = _toCkmCertificate(cert);
		if (!ckmCert)
			return CKMC_ERROR_INVALID_FORMAT;

		CKM::CertificateShPtrVector ckmCertChain;
		auto mgr = CKM::Manager::create();
		int ret = mgr->getCertificateChain(
			ckmCert,
			_toCkmCertificateVector(untrustedcerts),
			EMPTY_CERT_VECTOR,
			true,
			ckmCertChain);
		if (ret != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		*cert_chain_list = _toNewCkmCertList(ckmCertChain);

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain_with_alias(const ckmc_cert_s *cert, const ckmc_alias_list_s *untrustedcerts,
								   ckmc_cert_list_s **cert_chain_list) {
	return try_catch_enclosure([&]()->int {
		if (cert == nullptr || cert->raw_cert == nullptr || cert->cert_size == 0 || cert_chain_list == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto ckmCert = _toCkmCertificate(cert);
		if (!ckmCert)
			return CKMC_ERROR_INVALID_FORMAT;

		CKM::CertificateShPtrVector ckmCertChain;
		auto mgr = CKM::Manager::create();
		int ret = mgr->getCertificateChain(ckmCert, _toCkmAliasVector(untrustedcerts), EMPTY_ALIAS_VECTOR, true, ckmCertChain);
		if (ret != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		*cert_chain_list = _toNewCkmCertList(ckmCertChain);

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain_with_trustedcert(const ckmc_cert_s *cert,
		const ckmc_cert_list_s *untrustedcerts,
		const ckmc_cert_list_s *trustedcerts,
		const bool sys_certs,
		ckmc_cert_list_s **ppcert_chain_list) {
	return try_catch_enclosure([&]()->int {
		if (cert == nullptr || cert->raw_cert == nullptr || cert->cert_size == 0 || ppcert_chain_list == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto ckmCert = _toCkmCertificate(cert);
		if (!ckmCert)
			return CKMC_ERROR_INVALID_PARAMETER;

		CKM::CertificateShPtrVector ckmCertChain;
		auto mgr = CKM::Manager::create();
		int ret = mgr->getCertificateChain(
			ckmCert,
			_toCkmCertificateVector(untrustedcerts),
			_toCkmCertificateVector(trustedcerts),
			sys_certs,
			ckmCertChain);
		if (ret != CKM_API_SUCCESS)
			return to_ckmc_error(ret);

		*ppcert_chain_list = _toNewCkmCertList(ckmCertChain);

		return CKMC_ERROR_NONE;
	});
}

KEY_MANAGER_CAPI
int ckmc_ocsp_check(const ckmc_cert_list_s *pcert_chain_list, ckmc_ocsp_status_e *ocsp_status) {
	return try_catch_enclosure([&]()->int {
		if (pcert_chain_list == nullptr
		|| pcert_chain_list->cert == nullptr
		|| pcert_chain_list->cert->raw_cert == nullptr
		|| pcert_chain_list->cert->cert_size == 0
		|| ocsp_status == nullptr)
			return CKMC_ERROR_INVALID_PARAMETER;

		int tmpOcspStatus = -1;
		auto mgr = CKM::Manager::create();
		int ret = mgr->ocspCheck(_toCkmCertificateVector(pcert_chain_list), tmpOcspStatus);

		*ocsp_status = to_ckmc_ocsp_status(tmpOcspStatus);

		return to_ckmc_error(ret);
	});
}

KEY_MANAGER_CAPI
int ckmc_allow_access(const char *alias, const char *accessor, ckmc_access_right_e granted) {
	return try_catch_enclosure([&]()->int {
		int permissionMask;
		int ret = access_to_permission_mask(granted, permissionMask);

		if (ret != CKMC_ERROR_NONE)
			return ret;

		return ckmc_set_permission(alias, accessor, permissionMask);
	});
}

KEY_MANAGER_CAPI
int ckmc_set_permission(const char *alias, const char *accessor, int permissions) {
	return try_catch_enclosure([&]()->int {
		if (!alias || !accessor)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->setPermission(alias, accessor, permissions));
	});
}

KEY_MANAGER_CAPI
int ckmc_deny_access(const char *alias, const char *accessor) {
	return try_catch_enclosure([&]()->int {
		if (!alias || !accessor)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->setPermission(alias, accessor, CKM::Permission::NONE));
	});
}

KEY_MANAGER_CAPI
int ckmc_remove_alias(const char *alias) {
	return try_catch_enclosure([&]()->int {
		if (!alias)
			return CKMC_ERROR_INVALID_PARAMETER;

		auto mgr = CKM::Manager::create();
		return to_ckmc_error(mgr->removeAlias(alias));
	});
}

KEY_MANAGER_CAPI
int ckmc_encrypt_data(ckmc_param_list_h params,
					  const char *key_alias,
					  const char *password,
					  const ckmc_raw_buffer_s decrypted,
					  ckmc_raw_buffer_s **ppencrypted) {
	return try_catch_enclosure([&]()->int {
		return _cryptoOperation(&CKM::Manager::encrypt,
		params,
		key_alias,
		password,
		decrypted,
		ppencrypted);
	});
}

KEY_MANAGER_CAPI
int ckmc_decrypt_data(ckmc_param_list_h params,
					  const char *key_alias,
					  const char *password,
					  const ckmc_raw_buffer_s encrypted,
					  ckmc_raw_buffer_s **ppdecrypted) {
	return try_catch_enclosure([&]()->int {
		return _cryptoOperation(&CKM::Manager::decrypt,
		params,
		key_alias,
		password,
		encrypted,
		ppdecrypted);
	});
}
