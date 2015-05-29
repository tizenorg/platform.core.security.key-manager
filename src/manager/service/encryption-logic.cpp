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
#include <dpl/log/log.h>

namespace CKM {

EncryptionLogic::~EncryptionLogic()
{
    // TODO Auto-generated destructor stub
}

void EncryptionLogic::crypt(const CryptoRequest& request)
{
    auto ret = m_requests.insert(std::make_pair(request.msgId, request));
    if (!ret.second) {
        LogError("Request with id " << request.msgId << " already exists");
        m_service.RespondToClient(request, CKM_API_ERROR_INPUT_PARAM);
    }

    try {
        m_service.RequestKey(request.cred, request.name, request.label);
    } catch (...) {
        LogError("Key request failed");
        m_requests.erase(request.msgId);
        m_service.RespondToClient(request, CKM_API_ERROR_SERVER_ERROR);
    }
}

} /* namespace CKM */
