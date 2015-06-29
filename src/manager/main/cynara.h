/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cynara.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Support for cynara.
 */
#pragma once

#include <string>
#include <map>

#include <stdint.h>

#include <generic-socket-manager.h>
#include <cynara-client-async.h>

namespace CKM {

class Cynara {
public:
    Cynara(GenericSocketManager *socketManager);

    void request(int socket,
        const std::string &sockPriv,
        const std::function<void(void)> &accessGranted,
        const std::function<void(void)> &accessDenied);

    void processSocket();

    virtual ~Cynara();

protected:
    void changeStatus(int oldFd, int newFd, cynara_async_status status);
    void processResponse(uint16_t checkId, cynara_async_call_cause cause, int response);
    void sendRequest(
        const std::function<void(void)> &accessGranted,
        const std::function<void(void)> &accessDenied,
        const std::string &smack,
        const std::string &user,
        const std::string &privilege);
    static void changeStatusCallback(
        int oldFd,
        int newFd,
        cynara_async_status status,
        void *ptr);

    static void processResponseCallback(
        uint16_t checkId,
        cynara_async_call_cause cause,
        int response,
        void *ptr);

    struct Callbacks {
        std::function<void(void)> accessGranted;
        std::function<void(void)> accessDenied;
    };

    GenericSocketManager *m_socketManager;
    cynara_async *m_cynara;
    std::map<uint16_t, Callbacks> m_callbacksMap;
}; 

} // namespace CKM
