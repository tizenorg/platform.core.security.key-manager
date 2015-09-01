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
#include <ckm-logic-ext.h>

using namespace std;
using namespace CKM;

class DbWrapper {
public:
    DbWrapper(uid_t uid, Password pw) : m_uid(uid), m_pw(pw) {}

    int unlock();
    void lock();
    void process(const string& cmd);

private:
    uid_t m_uid;
    Password m_pw;
    CKMLogicExt m_logic;
};

int DbWrapper::unlock() {
    int retCode;
    RawBuffer ret = m_logic.unlockUserKey(m_uid, m_pw);
    MessageBuffer buff;
    buff.Push(ret);
    buff.Deserialize(retCode);
    return retCode;
}

void DbWrapper::lock() {
    m_logic.lockUserKey(m_uid);
}

void DbWrapper::process(const string& acmd) {
    try {
        string cmd = acmd;
        if (acmd == ".tables")
            cmd = "select name from sqlcipher_master where type='table' AND name!='sqlcipher_sequence'";
        else if(acmd == ".schema")
            cmd = "select * from sqlcipher_master where type='table' AND name!='sqlcipher_sequence'";

        DB::SqlConnection::Output output = m_logic.Execute(m_uid, cmd);

        if(output.names.empty())
            return;

        for(const auto& str : output.names)
            cout << str << "|";
        cout << endl << "--------------------------" << endl;
        for(const auto& row : output.values) {
            for(const auto& str : row)
                cout << str << "|";
            cout << endl;
        }
    } catch (const DB::SqlConnection::Exception::Base& e) {
        cout << e.GetMessage() << endl;
    }
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
            getline(cin, cmd);
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
