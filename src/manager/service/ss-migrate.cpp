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
 * @file        ss-migrate.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Deprecated secure-storage data migration
 */
#include <ss-migrate.h>

#include <fstream>
#include <memory>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <dpl/log/log.h>

namespace CKM {

namespace {

const std::string OLD_SS_DIR = RW_DATA_DIR "/secure-storage";
const std::string OLD_SS_GROUP_PREFIX = "secure-storage::";
const int SALT_SIZE = 32;
const int KEY_SIZE = 16;

std::unique_ptr<char[]> get_key(const std::string &id, size_t len)
{
	unsigned char salt[SALT_SIZE];

	::memset(salt, 0xFF, SALT_SIZE);

	std::unique_ptr<char[]> duk(new char[len + 1]);

	::PKCS5_PBKDF2_HMAC_SHA1(id.c_str(), id.length(), salt, SALT_SIZE, 1,
			len, reinterpret_cast<unsigned char *>(duk.get()));

	duk[len] = '\0';

	return duk;
}

RawBuffer read_data(const std::string &filepath, const std::string &seed)
{
	std::ifstream f(filepath.c_str(), std::ios::binary);

	if (!f.is_open()) {
		LogError("Failed to open file: " << filepath);
		return RawBuffer();
	}

	f.seekg(0, f.end);
	auto ciphertext_len = f.tellg();
	if (ciphertext_len == -1) {
		LogError("Failed to get file length: " << filepath);
		return RawBuffer();
	}

	f.seekg(0, f.beg);

	RawBuffer ciphertext(ciphertext_len, 0);

	f.read(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
	if (!f) {
		LogError("Failed to read file: " << filepath);
		return RawBuffer();
	}

	auto key = get_key(seed, KEY_SIZE);
	std::unique_ptr<char[]> iv(new char[KEY_SIZE]);
	size_t ivlen = 0;
	if (::EVP_Digest(key.get(), KEY_SIZE, reinterpret_cast<unsigned char *>(iv.get()),
				&ivlen, ::EVP_sha1(), nullptr) != 1) {
		LogError("Failed to get iv");
		// TODO: throw exception
		return RawBuffer();
	}

	// start decrypt data with key and iv
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

	ec = ::EVP_CipherInit(ctx, algo, reinterpret_cast<unsigned char *>(key.get()),
			reinterpret_cast<unsigned char *>(iv.get()), 0 /* decrypt flag */);
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

// depth 0 -> OLD_SS_DIR
//       1 -> group dir in OLD_SS_DIR
void visit_dir(const std::string &dirpath, struct dirent *buf, size_t depth,
			  const Saver &saver)
{
	if (depth > 1) {
		LogError("Invalid depth in secure-storage subdir... dirpath: " << dirpath);
		return;
	}

	std::unique_ptr<DIR, int(*)(DIR *)> dirptr(::opendir(dirpath.c_str()), ::closedir);
	if (dirptr == nullptr) {
		LogError("Failed to open dir: " << dirpath << " with errno: " << errno);
		return;
	}

	while (true) {
		struct dirent *result = nullptr;
		auto ret = ::readdir_r(dirptr.get(), buf, &result);
		if (ret != 0) {
			LogError("readdir_r error on secure-storage dir: " << dirpath <<
					 " with errno: " << errno);
			break;
		} else if (result == nullptr) {
			if (::rmdir(dirpath.c_str()) == -1)
				LogError("Failed to rmdir dir: " << dirpath << " with errno: " << errno);
			break;
		}

		const auto &name = result->d_name;
		auto name_size = ::strlen(name);

		if (result->d_type == DT_DIR) {
			if ((name_size == 1 && name[0] == '.') ||
				(name_size == 2 && name[0] == '.' && name[1] == '.')) {
				continue;
			} else if (depth == 1) {
				// TODO: how to remove this invalid directory?
				LogError("Invalid hierarchy of secure-storage dir... "
						 "Directory(" << name << ") cannot be in "
						 "group storage: " << dirpath);
			} else {
				std::string subdir = dirpath + "/" + name;
				visit_dir(subdir, buf, depth + 1, saver);
			}
		} else if (result->d_type == DT_REG) {
			if (depth == 0) {
				// TODO: how to remove this invalid file?
				LogError("Invalid hierarchy of secure-storage dir... "
						 "File(" << name << ") cannot be in secure-storage top dir");
			} else {
				std::string filepath = dirpath + "/" + name;
				LogInfo("Meet file(" << filepath << ") in secure-storage! "
						"Let's save it into key-manager.");

				auto storage_name = dirpath.substr(OLD_SS_DIR.length() + 1);

				Crypto::Data data;
				data.type = DataType::BINARY_DATA;
				data.data = read_data(filepath, storage_name);

				if (data.data.empty()) {
					LogError("Failed to read data from file: " << filepath);
				} else if (storage_name == "secure-storage") {
					LogInfo("Meet secure-storage storage which contains SALT! skip it!");
				} else if (storage_name.rfind(OLD_SS_GROUP_PREFIX) == std::string::npos) {
					LogInfo("data file(" << filepath << ") is not in group! smack-label is used as storage name");
					saver(storage_name, name, data);
				} else {
					LogInfo("data file(" << filepath << ") is in group! group id is extracted from dir path");
					saver(storage_name.substr(OLD_SS_GROUP_PREFIX.length()), name, data);
				}

				if (::unlink(filepath.c_str()) == -1)
					LogError("Failed to unlink file: " << filepath <<
							 " with errno: " << errno);
			}
		} else {
			// TODO: how to remove this invalid file?
			LogError("Invalid type(" << result->d_type << ") of file(" << name << ") "
					 "in dir: " << dirpath);
		}
	}
}

} // namespace anonymous

bool hasMigratableData(void)
{
	if (::access(OLD_SS_DIR.c_str(), R_OK | X_OK) == -1) {
		const int err = errno;

		if (err != ENOENT)
			LogError("Failed to access old secure-storage dir. errno: " << err);

		return false;
	} else {
		return true;
	}
}

void migrateData(const Saver &saver)
{
	if (saver == nullptr) {
		LogError("saver cannot be null");
		return;
	}

	std::unique_ptr<struct dirent, void(*)(void *)> bufptr(
			static_cast<struct dirent *>(::malloc(
					offsetof(struct dirent, d_name) + NAME_MAX + 1)), ::free);

	if (bufptr == nullptr)
		throw std::bad_alloc();

	visit_dir(OLD_SS_DIR, bufptr.get(), 0, saver);
}

}
