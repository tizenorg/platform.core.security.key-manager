/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        assert.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of assert
 */
#include "dpl/assert.h"

#include <iostream>
#include <cstdlib>
#include <dpl/log/log.h>

namespace CKM {
void AssertProc(const char *condition,
                const char *file,
                int line,
                const char *function)
{
    try {
        LogError(
            "################################################################################" << std::endl <<
            "###                          CKM assertion failed!                           ###" << std::endl <<
            "################################################################################" << std::endl <<
            "### Condition: " << condition << std::endl <<
            "### File: " << file << std::endl <<
            "### Line: " << line << std::endl <<
            "### Function: " << function <<
            "################################################################################");
    } catch (...) {
        // Just ignore possible double errors
    }

    // Fail with c-library abort
    abort();
}
} // namespace CKM
