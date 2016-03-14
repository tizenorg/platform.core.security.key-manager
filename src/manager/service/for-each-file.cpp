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
 * @file        for-each-file.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Handle all files in the directory by given function.
 */
#include "for-each-file.h"

#include <memory>
#include <cstddef>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>

#include <dpl/errno_string.h>
#include <exception.h>

namespace CKM {

void forEachFile(const std::string &dirpath, ActionFunc func)
{
    std::unique_ptr<DIR, std::function<int(DIR*)>>
        dirp(::opendir(dirpath.c_str()), ::closedir);

    if (!dirp.get())
        ThrowErr(Exc::FileSystemFailed,
            "Cannot open dir: ", dirpath, " errno: ", GetErrnoString());

    size_t len =
        offsetof(struct dirent, d_name) + pathconf(dirpath.c_str(), _PC_NAME_MAX) + 1;

    std::unique_ptr<struct dirent, std::function<void(void*)>>
        pEntry(static_cast<struct dirent*>(::malloc(len)), ::free);

    if (!pEntry)
        ThrowErr(Exc::InternalError, "Memory allocation failed for dir entry");

    struct dirent *pDirEntry = nullptr;

    while ((!readdir_r(dirp.get(), pEntry.get(), &pDirEntry)) && pDirEntry) {
        /* run func for every file names in dirpath. d_name is only file name, not path */
        func(pDirEntry->d_name);
    }
}

}
