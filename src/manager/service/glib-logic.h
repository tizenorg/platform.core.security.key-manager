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
 * @file        glib-logic.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */
#pragma once

#include <glib.h>

#include <noncopyable.h>
#include <package-manager.h>
#include <service-messages.h>

namespace CKM {

class GLIBLogic {
public:
    GLIBLogic();

    NONCOPYABLE(GLIBLogic);

    void LoopStart();
    void LoopStop();
    void SetCommManager(CommMgr *manager);
    virtual ~GLIBLogic();

protected:
    static int packageEventCallbackStatic(
        uid_t uid,
        int reqid,
        const char *pkgtype,
        const char *pkgid,
        const char *key,
        const char *val,
        const void *pmsg,
        void *data);

    int packageEventCallback(
        uid_t uid,
        int reqid,
        const char *pkgtype,
        const char *pkgid,
        const char *key,
        const char *val,
        const void *pmsg,
        void *data);

    CommMgr *m_commMgr;
    GMainLoop *m_gMainLoop;
    int m_reqid;
};

} // namespace CKM

