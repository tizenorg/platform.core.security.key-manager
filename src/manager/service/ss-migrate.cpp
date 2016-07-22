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
#include <cerrno>
#include <cstddef>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <dpl/log/log.h>
#include <ss-crypto.h>

namespace CKM {
namespace SsMigration {

namespace {

const std::string OLD_SS_DIR = RW_DATA_DIR "/secure-storage";

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

	return SsMigration::decrypt(seed, ciphertext);
}

inline void remove_path(const std::string &path, bool isAdminUser)
{
	if (!isAdminUser)
		return;

	if (::remove(path.c_str()) == -1)
		LogError("Failed to remove path: " << path << " with errno: " << errno);

	LogInfo("File removed: " << path);
}

// depth 0 -> OLD_SS_DIR
//       1 -> group dir in OLD_SS_DIR
void visit_dir(const std::string &dirpath, struct dirent *buf, size_t depth,
			   const Saver &saver, bool isAdminUser)
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
			remove_path(dirpath, isAdminUser);
			break;
		}

		const auto &name = result->d_name;
		auto name_size = ::strlen(name);

		std::string path = dirpath + "/" + name;
		if (result->d_type == DT_DIR) {
			if ((name_size == 1 && name[0] == '.') ||
				(name_size == 2 && name[0] == '.' && name[1] == '.')) {
				continue;
			} else if (depth == 1) {
				LogError("Invalid hierarchy of secure-storage dir... "
						 "Directory(" << name << ") cannot be in "
						 "group storage: " << dirpath);
			} else {
				std::string subdir = dirpath + "/" + name;
				visit_dir(subdir, buf, depth + 1, saver, isAdminUser);
				continue;
			}
		} else if (result->d_type == DT_REG) {
			if (depth == 0) {
				LogError("Invalid hierarchy of secure-storage dir... "
						 "File(" << name << ") cannot be in secure-storage top dir");
			} else {
				LogInfo("Meet file(" << path << ") in secure-storage! "
						"Let's save it into key-manager.");

				auto storage_name = dirpath.substr(OLD_SS_DIR.length() + 1);

				Crypto::Data data;
				data.type = DataType::BINARY_DATA;
				data.data = read_data(path, storage_name);

				if (data.data.empty())
					LogError("Failed to read data from file: " << path);
				else if (storage_name == "secure-storage")
					LogInfo("Meet secure-storage storage which contains SALT! skip it!");
				else
					saver(name, data, isAdminUser);
			}
		} else {
			LogError("Invalid type(" << result->d_type << ") of file(" << path << ") ");
		}

		remove_path(path, isAdminUser);
	}
}

} // namespace anonymous

bool hasData(void)
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

void migrate(bool isAdminUser, const Saver &saver)
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

	visit_dir(OLD_SS_DIR, bufptr.get(), 0, saver, isAdminUser);
}

} // namespace SsMigration
} // namespace CKM
