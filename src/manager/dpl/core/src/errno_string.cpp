/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        errno_string.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewskik@samsung.com)
 * @version     1.0
 * @brief       Get errno string as std::string by strerror_r
 */
#include "dpl/errno_string.h"

#include <cstddef>
#include <cerrno>
#include <vector>

namespace CKM {
namespace { // anonymous

const size_t MAX_BUF = 256;

} // namespace anonymous

std::string GetErrnoString(int error)
{
    std::vector<char> buffer(MAX_BUF, '\0');

#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE

    if (0 == strerror_r(error, buffer.data(), buffer.size()))
        return std::string(buffer.begin(), buffer.end());

#else
    char *result = strerror_r(error, buffer.data(), buffer.size());

    if (result)
        return std::string(result);

#endif

    return std::string();
}
} // namespace CKM
