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
 *
 * @file        ss-crypto.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Decrypt old secure-storage data for migration
 */
#include <ss-crypto.h>

#include <memory>
#include <cstring>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <dpl/log/log.h>

namespace CKM {

namespace {

const int SALT_SIZE = 32;
const int KEY_SIZE = 16;

RawBuffer _get_key(const std::string &id)
{
	unsigned char salt[SALT_SIZE];

	::memset(salt, 0xFF, SALT_SIZE);

	RawBuffer duk(KEY_SIZE);

	if (::PKCS5_PBKDF2_HMAC_SHA1(id.c_str(), id.length(), salt, SALT_SIZE, 1, duk.size(),
			duk.data()) != 1) {
		LogError("Failed to pkcs5_pkbdf_hmac_sha1.");
		return RawBuffer();
	}

	return duk;
}

RawBuffer _get_iv(const RawBuffer &src)
{
	RawBuffer iv(KEY_SIZE);
	size_t ivlen = iv.size();

	if (::EVP_Digest(src.data(), src.size(), iv.data(), &ivlen, ::EVP_sha1(), nullptr)
			!= 1) {
		LogError("Failed to get iv");
		return RawBuffer();
	}

	return iv;
}

RawBuffer _decrypt(const RawBuffer &key, const RawBuffer &iv, const RawBuffer &ciphertext)
{
	auto algo = ::EVP_aes_128_cbc();
	int tmp_len = (ciphertext.size() / algo->block_size + 1) * algo->block_size;

	RawBuffer plaintext(tmp_len, 0);

	std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX *)> ctxptr(
			::EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

	if (ctxptr == nullptr)
		throw std::bad_alloc();

	auto ctx = ctxptr.get();

	int ec = ::EVP_CIPHER_CTX_set_padding(ctx, 1);
	if (ec != 1) {
		LogError("Failed to evp ctx set padding. ec: " << ec);
		return RawBuffer();
	}

	ec = ::EVP_CipherInit(ctx, algo, key.data(), iv.data(), 0 /* decrypt flag */);
	if (ec != 1) {
		LogError("Failed to evp cipher init. ec: " << ec);
		return RawBuffer();
	}

	int plaintext_len = 0;
	ec = ::EVP_CipherUpdate(ctx, plaintext.data(), &plaintext_len,
			ciphertext.data(), ciphertext.size());
	if (ec != 1) {
		LogError("Failed to evp cipher update. ec: " << ec);
		return RawBuffer();
	}

	int final_len = 0;
	ec = EVP_CipherFinal(ctx, plaintext.data() + plaintext_len, &final_len);
	if (ec != 1) {
		LogError("Failed to evp cipher final. ec: " << ec);
		return RawBuffer();
	}

	plaintext_len += final_len;

	plaintext.resize(plaintext_len);

	return plaintext;
}

} // namespace anonymous

namespace SsMigration {

RawBuffer decrypt(const std::string &seed, const RawBuffer &ciphertext)
{
	auto key = _get_key(seed);
	auto iv = _get_iv(key);

	return _decrypt(key, iv, ciphertext);
}

} // namespace SsMigration

} // namespace CKM
