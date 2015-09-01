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
 * @file       ckm-logic-ext.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <ckm-logic-ext.h>
#include <db-crypto-ext.h>

namespace CKM {

DB::SqlConnection::Output CKMLogicExt::Execute(uid_t user, const std::string& cmd) {
    DB::SqlConnection::Output output;
    DB::CryptoExt db(std::move(m_userDataMap[user].database));
    try {
        output = db.Execute(cmd);
        m_userDataMap[user].database = std::move(*static_cast<DB::Crypto*>(&db));
        return output;
    } catch (const DB::SqlConnection::Exception::Base& e) {
        m_userDataMap[user].database = std::move(*static_cast<DB::Crypto*>(&db));
        throw;
    }
}

} // namespace CKM


