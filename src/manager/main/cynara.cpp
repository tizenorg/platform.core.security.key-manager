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
 * @file        cynara.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Support for cynara.
 */
#include <string>
#include <map>

#include <stdint.h>

#include <dpl/log/log.h>
#include <cynara.h>

#include <cynara-creds-socket.h>
#include <cynara-client-async.h>

namespace CKM {

Cynara::Cynara(GenericSocketManager *socketManager)
  : m_socketManager(socketManager)
  , m_cynara(nullptr)
{
    if (CYNARA_API_SUCCESS != cynara_async_initialize(&m_cynara, NULL, changeStatusCallback, this)) {
        LogError("Cynara initialization failed.");
        throw std::runtime_error("Cynara initialization failed.");
    }
}

void Cynara::Request(
    int socket,
    int session,
    const std::string &sockPriv,
    StatusCallback callback)
{
    char *ptr;

    if (CYNARA_API_SUCCESS != cynara_creds_socket_get_client(socket, CLIENT_METHOD_DEFAULT, &ptr))
        return callback(false);

    std::string smack(ptr);
    free(ptr);

    if (CYNARA_API_SUCCESS != cynara_creds_socket_get_user(socket, USER_METHOD_DEFAULT, &ptr))
        return callback(false);

    std::string user(ptr);
    free(ptr);

    std::string ses = std::to_string(session);

    int ret = cynara_async_check_cache(
      m_cynara,
      smack.c_str(),
      ses.c_str(),
      user.c_str(),
      sockPriv.c_str());

    switch(ret) {
    default:
    case CYNARA_API_ACCESS_DENIED:
        callback(false);
        break;
    case CYNARA_API_ACCESS_ALLOWED:
        callback(true);
        break;
    case CYNARA_API_CACHE_MISS:
        sendRequest(
            std::move(callback),
            smack,
            user,
            sockPriv,
            ses);
    }
}

void Cynara::processSocket() {
    if (CYNARA_API_SUCCESS != cynara_async_process(m_cynara)) {
        LogError("Function: cynara_async_process failed.");
    }
}

Cynara::~Cynara(){
    cynara_async_finish(m_cynara);
}

void Cynara::changeStatus(int oldFd, int newFd, cynara_async_status status) {
    m_socketManager->CynaraSocket(oldFd, newFd, status == CYNARA_STATUS_FOR_RW);
}

void Cynara::processResponse(uint16_t checkId, cynara_async_call_cause cause, int response) {
    auto it = m_callbackMap.find(checkId);

    if (it == m_callbackMap.end())
        return;

    if (cause == CYNARA_CALL_CAUSE_ANSWER && response == CYNARA_API_ACCESS_ALLOWED)
        it->second(true);
    else
        it->second(false);

    m_callbackMap.erase(it);
}
void Cynara::sendRequest(
    StatusCallback callback,
    const std::string &smack,
    const std::string &user,
    const std::string &privilege,
    const std::string &session)
{
    cynara_check_id checkId = 0;
    int ret = cynara_async_create_request(
        m_cynara,
        smack.c_str(),
        session.c_str(),
        user.c_str(),
        privilege.c_str(),
        &checkId,
        processResponseCallback,
        this);

    if (ret != CYNARA_API_SUCCESS)
        return callback(false);

    m_callbackMap.emplace(checkId, std::move(callback));
}

void Cynara::changeStatusCallback(
  int oldFd,
  int newFd,
  cynara_async_status status,
  void *ptr)
{
    static_cast<Cynara*>(ptr)->changeStatus(oldFd, newFd, status);
}

void Cynara::processResponseCallback(
  uint16_t checkId,
  cynara_async_call_cause cause,
  int response,
  void *ptr)
{
    static_cast<Cynara*>(ptr)->processResponse(checkId, cause, response);
}

} // namespace CKM
