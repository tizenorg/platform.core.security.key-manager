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
 * @file        dbus-service.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */

#include <thread>

#include <dbus-service.h>
#include <dbus-logic.h>

namespace CKM {

DBUSService::DBUSService()
  : m_logic(new DBUSLogic())
{}

void DBUSService::Event(const AcceptEvent &) {}
void DBUSService::Event(const WriteEvent &) {}
void DBUSService::Event(const ReadEvent &) {}
void DBUSService::Event(const CloseEvent &) {}
void DBUSService::Event(const SecurityEvent &) {}

void DBUSService::Start(){
    assert(m_state == State::NoThread);
    m_thread = std::thread(ThreadLoopStatic, this);
    m_state = State::Work;
}

void DBUSService::Stop(){
    assert(m_state == State::Work);
    assert(m_gMainLoop);
    m_logic->LoopStop();
    m_thread.join();
    m_state = State::NoThread;
}

DBUSService::~DBUSService(){
    delete m_logic;
}

ServiceDescriptionVector DBUSService::GetServiceDescription() {
    return ServiceDescriptionVector();
}

void DBUSService::ThreadLoopStatic(DBUSService *ptr) {
    ptr->ThreadLoop();
}

void DBUSService::ThreadLoop() {
    m_logic->LoopStart();
}

void DBUSService::SetCommManager(CommMgr *manager) {
    m_commMgr = manager;
    m_logic->SetCommManager(manager);
}

} // namespace CKM

