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

#include <cynara.h>

#include <cynara-creds-socket.h>
#include <cynara-client-async.h>

namespace CKM {

Cynara::Cynara(GenericSocketManager *socketManager)
  : m_socketManager(socketManager)
  , m_cynara(nullptr)
{
    cynara_async_initialize(&m_cynara, NULL, changeStatusCallback, this);
}

void Cynara::request(int socket,
  const std::string &sockPriv,
  const std::function<void(void)> &accessGranted,
  const std::function<void(void)> &accessDenied)
{
    char *ptr;

    if (CYNARA_API_SUCCESS != cynara_creds_socket_get_client(socket, CLIENT_METHOD_DEFAULT, &ptr))
        return accessDenied();

    std::string smack(ptr);
    free(ptr);

    if (CYNARA_API_SUCCESS != cynara_creds_socket_get_user(socket, USER_METHOD_DEFAULT, &ptr))
        return accessDenied();

    std::string user(ptr);
    free(ptr);

    int ret = cynara_async_check_cache(
      m_cynara,
      smack.c_str(),
      "",
      user.c_str(),
      sockPriv.c_str());

    switch(ret) {
    default:
    case CYNARA_API_ACCESS_DENIED:
        accessDenied();
        break;
    case CYNARA_API_ACCESS_ALLOWED:
        accessGranted();
        break;
    case CYNARA_API_CACHE_MISS:
        sendRequest(
          accessGranted,
          accessDenied,
          smack,
          user,
          sockPriv);
    }
}

void Cynara::processSocket() {
    cynara_async_process(m_cynara);
}

Cynara::~Cynara(){
    cynara_async_finish(m_cynara);
}

void Cynara::changeStatus(int oldFd, int newFd, cynara_async_status status) {
    m_socketManager->CynaraSocket(oldFd, newFd, status == CYNARA_STATUS_FOR_RW);
}

void Cynara::processResponse(uint16_t checkId, cynara_async_call_cause cause, int response) {
    auto it = m_callbacksMap.find(checkId);
    if (it == m_callbacksMap.end()) {
        return;
    }

    if (cause == CYNARA_CALL_CAUSE_ANSWER && response == CYNARA_API_ACCESS_ALLOWED)
        it->second.accessGranted();
    else
        it->second.accessDenied();

    m_callbacksMap.erase(it);
}
void Cynara::sendRequest(
  const std::function<void(void)> &accessGranted,
  const std::function<void(void)> &accessDenied,
  const std::string &smack,
  const std::string &user,
  const std::string &privilege)
{
    cynara_check_id checkId = 0;
    int ret = cynara_async_create_request(
      m_cynara,
      smack.c_str(),
      "",
      user.c_str(),
      privilege.c_str(),
      &checkId,
      processResponseCallback,
      this);

    if (ret != CYNARA_API_SUCCESS) {
        accessDenied();
        return;
    }

    Callbacks call = {accessGranted, accessDenied};
    m_callbacksMap[checkId] = call;
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
