/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       exception.h
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once

#include <exception.h>

namespace CKM {
namespace Crypto {
namespace Exception {

typedef CKM::Ex::InputParam InputParam;
typedef CKM::Ex::InternalError InternalError;
typedef CKM::Ex::InternalError KeyNotSupported;
typedef CKM::Ex::InternalError OperationNotSupported;
typedef CKM::Ex::InternalError WrongBackend;

} // namespace Ex
} // namespace Crypto
} // namespace CKM

