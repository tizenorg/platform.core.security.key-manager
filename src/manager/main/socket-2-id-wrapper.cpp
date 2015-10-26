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
 * @file       socket-2-id-wrapper.cpp
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <string>

#include <security-manager.h>

#include <dpl/log/log.h>
#include <protocols.h>
#include <socket-2-id.h>

namespace {

int getPkgIdFromSmack(int sock, std::string &pkgId) {
    char *pkg = nullptr;

    int ret = security_manager_identify_app_from_socket(sock, &pkg, nullptr);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        LogError("security_manager_identify_app_from_socket failed with error: "
                 << ret);
        return -1;
    }

    pkgId = pkg;
    free(pkg);
    LogDebug("Socket: " << sock << " Was translated to owner id: " << pkgId);
    return 0;
}

} // namespace anonymous

namespace CKM {

int Socket2Id::translate(int sock, std::string &result) {
    std::string smack;

    if (0 > getCredentialsFromSocket(sock, smack)) {
        return -1;
    }

    StringMap::iterator it = m_stringMap.find(smack);

    if (it != m_stringMap.end()) {
        result = it->second;
        return 0;
    }

    std::string pkgId;
    if (0 > getPkgIdFromSmack(sock, pkgId)) {
        return -1;
    }

    result = pkgId;
    m_stringMap.emplace(std::move(smack), std::move(pkgId));
    return 0;
}

} // namespace CKM

