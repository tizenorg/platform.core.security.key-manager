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
 * @file       encryption-logic.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <encryption-logic.h>
#include <ckm/ckm-error.h>

namespace CKM {

EncryptionLogic::EncryptionLogic()
{
    // TODO Auto-generated constructor stub

}

EncryptionLogic::~EncryptionLogic()
{
    // TODO Auto-generated destructor stub
}

int EncryptionLogic::crypt(const Credentials &/*cred*/,
                           const CryptoAlgorithm& /*ca*/,
                           const Name& /*name*/,
                           const Label& /*label*/,
                           const Password& /*password*/,
                           const RawBuffer& /*input*/,
                           RawBuffer& /*output*/,
                           bool /*encrypt*/)
{
    return CKM_API_ERROR_SERVER_ERROR;
}

} /* namespace CKM */
