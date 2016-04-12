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

#include <set>
#include <memory>

#include <glib.h>
#include <package-manager.h>

#include <dpl/log/log.h>
#include <glib-logic.h>

namespace {
struct PkgmgrEvent {
	PkgmgrEvent(uid_t _uid, const char *_pkgid)
		: uid(_uid)
		, pkgid(_pkgid) {}

	inline bool operator==(const PkgmgrEvent &rhs) const
	{
		return uid == rhs.uid && pkgid.compare(rhs.pkgid) == 0;
	}

	inline bool operator<(const PkgmgrEvent &rhs) const
	{
		if (uid < rhs.uid)
			return true;
		else if (uid > rhs.uid)
			return false;
		else
			return pkgid.compare(rhs.pkgid) < 0;
	}

	inline bool operator>(const PkgmgrEvent &rhs) const
	{
		if (uid > rhs.uid)
			return true;
		else if (uid < rhs.uid)
			return false;
		else
			return pkgid.compare(rhs.pkgid) > 0;
	}

	uid_t uid;
	std::string pkgid;
};

std::set<PkgmgrEvent> pkgmgrEventSet;

}

namespace CKM {

GLIBLogic::GLIBLogic() : m_commMgr(nullptr), m_reqid(0)
{
	LogDebug("Allocation g_main_loop");
	m_gMainLoop = g_main_loop_new(nullptr, FALSE);
}

void GLIBLogic::LoopStart()
{
	LogDebug("Register uninstalledApp event callback start");

	std::unique_ptr<pkgmgr_client, int(*)(pkgmgr_client *)> client(
		pkgmgr_client_new(PC_LISTENING), pkgmgr_client_free);

	if (!client) {
		LogError("Error in pkgmgr_client_new");
		return;
	}

	m_reqid = pkgmgr_client_listen_status(client.get(), packageEventCallbackStatic,
										  this);

	if (m_reqid < 0) {
		LogError("Error in pkgmgr_client_listen_status. reqid(errcode): " << m_reqid);
		return;
	}

	LogDebug("Starting g_main_loop");
	g_main_loop_run(m_gMainLoop);
	LogDebug("...g_main_loop ended");
}

void GLIBLogic::LoopStop()
{
	LogDebug("Closing g_main_loop");
	g_main_loop_quit(m_gMainLoop);
}

GLIBLogic::~GLIBLogic()
{
	LogDebug("Destroying g_main_loop");
	g_main_loop_unref(m_gMainLoop);
}

void GLIBLogic::SetCommManager(CommMgr *manager)
{
	m_commMgr = manager;
}

int GLIBLogic::packageEventCallbackStatic(
	uid_t uid,
	int reqid,
	const char *pkgtype,
	const char *pkgid,
	const char *key,
	const char *val,
	const void *pmsg,
	void *data)
{
	LogDebug("Some event was caught");

	if (!data)
		return -1;
	else
		return static_cast<GLIBLogic *>(data)->packageEventCallback(
				   uid,
				   reqid,
				   pkgtype,
				   pkgid,
				   key,
				   val,
				   pmsg,
				   data);
}

int GLIBLogic::packageEventCallback(
	uid_t uid,
	int reqid,
	const char */*pkgtype*/,
	const char *pkgid,
	const char *key,
	const char *val,
	const void */*pmsg*/,
	void */*data*/)
{
	if (reqid != m_reqid) {
		LogError("pkgmgr event reqid[" << reqid
				 << "] isn't same with mine[" << m_reqid << "]");
		return -1;
	} else if (pkgid == nullptr || key == nullptr || val == nullptr) {
		LogError("Invalid parameter.");
		return -1;
	}

	PkgmgrEvent event(uid, pkgid);
	std::string keystr(key);
	std::string valstr(val);

	if (keystr.compare("start") == 0 && valstr.compare("uninstall") == 0) {
		pkgmgrEventSet.insert(event);
	} else if (keystr.compare("end") == 0 && valstr.compare("ok") == 0) {
		if (pkgmgrEventSet.count(event) != 0) {
			LogDebug("PackageUninstalled Callback. Uninstallation of: " << event.pkgid);
			m_commMgr->SendMessage(MsgRemoveAppData(event.pkgid));
			pkgmgrEventSet.erase(event);
		}
	}

	return 0;
}

} // namespace CKM

