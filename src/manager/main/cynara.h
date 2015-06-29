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
    typedef std::function<void(bool)> StatusCallback;
    explicit Cynara(GenericSocketManager *socketManager);

    Cynara& operator=(const Cynara &) = delete;

    void Request(
        const std::string &user,
        const std::string &client,
        const std::string &session,
        const std::string &privilege,
        StatusCallback callback);

    void processSocket();

    virtual ~Cynara();

    static bool GetUserFromSocket(int socket, std::string &user);
    static bool GetClientFromSocket(int socket, std::string &client);

protected:
    void changeStatus(int oldFd, int newFd, cynara_async_status status);
    void processResponse(uint16_t checkId, cynara_async_call_cause cause, int response);
    void SendRequest(
        const std::string &user,
        const std::string &client,
        const std::string &session,
        const std::string &privilege,
        StatusCallback callback);
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

    GenericSocketManager *m_socketManager;
    cynara_async *m_cynara;
    std::map<uint16_t, StatusCallback> m_callbackMap;
};

} // namespace CKM
