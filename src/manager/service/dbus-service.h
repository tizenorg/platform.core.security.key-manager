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
 *
 *
 * @file        dbus-service.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */
#pragma once

#include <thread>

#include <generic-socket-manager.h>

namespace CKM {

class DBUSLogic;

class DBUSService : public CKM::GenericSocketService {
public:
    enum class State {
        NoThread,
        Work,
    };

    DBUSService();
    DBUSService(const DBUSService &) = delete;
    DBUSService(DBUSService &&) = delete;
    DBUSService& operator=(const DBUSService &) = delete;
    DBUSService& operator=(DBUSService &&) = delete;

    // This service does not provide any socket for communication so no events will be supported
    virtual void Event(const AcceptEvent &);
    virtual void Event(const WriteEvent &);
    virtual void Event(const ReadEvent &);
    virtual void Event(const CloseEvent &);
    virtual void Event(const SecurityEvent &);

    virtual void Start();
    virtual void Stop();

    virtual ~DBUSService();

    virtual ServiceDescriptionVector GetServiceDescription();
    virtual void SetCommManager(CommMgr *manager);
protected:
    static void ThreadLoopStatic(DBUSService *ptr);
    void ThreadLoop();

    std::thread m_thread;
    DBUSLogic *m_logic;
};

} // namespace CKM

