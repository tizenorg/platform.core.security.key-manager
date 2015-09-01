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
 * @file       ckm_db_tool.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <iostream>
#include <sstream>
#include <exception>

#include <ckm-logic-ext.h>

#include <ckm/ckm-type.h>
#include <ckm/ckm-error.h>
#include <message-buffer.h>
#include <dpl/db/sql_connection.h>
#include <exception.h>

using namespace std;
using namespace CKM;

namespace {
const size_t MAX_LEN = 32;
const char ELLIPSIS[] = "...";
const size_t ELLIPSIS_LEN = sizeof(ELLIPSIS)/sizeof(ELLIPSIS[0]);
} // namespace anonymous

class DbWrapper {
public:
    DbWrapper(uid_t uid, Password pw) : m_uid(uid), m_pw(pw) {}

    int unlock();
    void lock();
    void process(const string& cmd);

private:
    void displayRow(const DB::SqlConnection::Output::Row& row);

    uid_t m_uid;
    Password m_pw;
    CKMLogicExt m_logic;
};

int DbWrapper::unlock()
{
    // no unlock for system db
    if (m_uid < 5000)
        return CKM_API_SUCCESS;

    int retCode;
    RawBuffer ret = m_logic.unlockUserKey(m_uid, m_pw);
    MessageBuffer buff;
    buff.Push(ret);
    buff.Deserialize(retCode);
    return retCode;
}

void DbWrapper::lock()
{
    // no lock for system db
    if (m_uid < 5000)
        return;

    m_logic.lockUserKey(m_uid);
}

void DbWrapper::process(const string& acmd)
{
    try {
        string cmd = acmd;
        if (acmd == ".tables")
            cmd = "SELECT name FROM sqlcipher_master "
                  "WHERE type IN ('table','view') AND name NOT LIKE 'sqlcipher_%' "
                  "UNION ALL "
                  "SELECT name FROM sqlcipher_temp_master "
                  "WHERE type IN ('table','view') "
                  "ORDER BY 1";
        else if(acmd == ".schema")
            cmd = "SELECT sql FROM "
                  "(SELECT * FROM sqlcipher_master "
                  "UNION ALL "
                  "SELECT * FROM sqlcipher_temp_master) "
                  "WHERE type!='meta' AND sql!='NULL'"
                  "ORDER BY tbl_name, type DESC, name";

        DB::SqlConnection::Output output = m_logic.Execute(m_uid, cmd);

        if(output.GetNames().empty())
            return;

        displayRow(output.GetNames());
        cout << "--------------------------" << endl;
        for(const auto& row : output.GetValues()) {
            displayRow(row);
        }
    } catch (const DB::SqlConnection::Exception::Base& e) {
        cout << e.GetMessage() << endl;
    } catch (const Exc::Exception &e) {
        cout << e.message() << endl;
    } catch (const std::exception &e) {
        cout << e.what() << endl;
    } catch (...) {
        cout << "Unexpected exception occurred" << endl;
    }
}

void DbWrapper::displayRow(const DB::SqlConnection::Output::Row& row)
{
    for(auto it = row.begin();it != row.end();it++) {
        std::string col = *it;
        if(col.size() > MAX_LEN) {
            col.resize(MAX_LEN);
            col.replace(MAX_LEN-ELLIPSIS_LEN, ELLIPSIS_LEN, ELLIPSIS);
        }
        cout << col;
        if(it+1 != row.end())
            cout<< "|";
    }
    cout << endl;
}

int main(int argc, char* argv[])
{
    if(argc < 2 || !argv[1]) {
        cout << "Provide user uid" << endl;
        return -1;
    }
    // read uid
    stringstream ss(argv[1]);
    uid_t uid;
    ss >> uid;

    // read password
    Password pass;
    if(argc > 2)
        pass = argv[2];

    // 3rd argument as a command
    string argcmd;
    if(argc > 3)
        argcmd = argv[3];

    // unlock db
    DbWrapper dbw(uid, pass);
    int retCode = dbw.unlock();
    if (retCode != CKM_API_SUCCESS ) {
        cout << "Unlocking database failed: " << retCode << endl;
        return -1;
    }
    cout << "Database unlocked" << endl;

    for(;;) {
        string cmd;
        if (argcmd.empty()) {
            cout << "> ";
            if(!getline(cin, cmd)) {
                cout << "exit" << endl;
                break; // EOF
            }
        } else {
            cmd = argcmd;
        }

        if(cmd == "exit")
            break;

        dbw.process(cmd);

        if(!argcmd.empty())
            break;
    }
    dbw.lock();
    cout << "Database locked" << endl;

    return 0;
}
