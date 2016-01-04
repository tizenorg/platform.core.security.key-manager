/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        glib-logic.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */
#include <fcntl.h>
#include <unistd.h>

#include <glib.h>
#include <package_manager.h>

#include <dpl/log/log.h>
#include <glib-logic.h>

namespace CKM {

GLIBLogic::GLIBLogic()
  : m_commMgr(nullptr)
{
    m_gMainLoop = g_main_loop_new(nullptr, FALSE);
}

void GLIBLogic::LoopStart() {
    package_manager_h request;
    package_manager_create(&request);
    LogDebug("Register uninstalledApp event callback start");
    if (0 != package_manager_set_event_cb(request, packageEventCallbackStatic, this)) {
        LogError("Error in package_manager_set_event_cb");
    }
    g_main_loop_run(m_gMainLoop);
}

void GLIBLogic::LoopStop() {
    g_main_loop_quit(m_gMainLoop);
}

GLIBLogic::~GLIBLogic() {
    g_main_loop_unref(m_gMainLoop);
}

void GLIBLogic::SetCommManager(CommMgr *manager) {
    m_commMgr = manager;
}

void GLIBLogic::packageEventCallbackStatic(
        const char *type,
        const char *package,
        package_manager_event_type_e eventType,
        package_manager_event_state_e eventState,
        int progress,
        package_manager_error_e error,
        void *userData)
{
    if (!userData)
        return;

    static_cast<GLIBLogic*>(userData)->packageEventCallback(
        type,
        package,
        eventType,
        eventState,
        progress,
        error);
}

void GLIBLogic::packageEventCallback(
        const char *type,
        const char *package,
        package_manager_event_type_e eventType,
        package_manager_event_state_e eventState,
        int progress,
        package_manager_error_e error)
{
    (void) type;
    (void) progress;
    (void) error;

    if (eventType != PACKAGE_MANAGER_EVENT_TYPE_UNINSTALL
            || eventState != PACKAGE_MANAGER_EVENT_STATE_STARTED
            || package == NULL)
    {
        return;
    }

    LogDebug("PackageUninstalled Callback. Uninstalation of: " << package);

    m_commMgr->SendMessage(MsgRemoveAppData(std::string(package)));
}

} // namespace CKM

