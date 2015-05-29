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
 * @file       encryption-service.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <encryption-service.h>
#include <protocols.h>
#include <dpl/log/log.h>
#include <dpl/serialization.h>

namespace {
const CKM::InterfaceID SOCKET_ID_ENCRYPTION = 0;
} // namespace anonymous

namespace CKM {

EncryptionService::EncryptionService()
{
}

EncryptionService::~EncryptionService()
{
}

GenericSocketService::ServiceDescriptionVector EncryptionService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_ENCRYPTION, "key-manager::api-encryption", SOCKET_ID_ENCRYPTION}
    };
}

bool EncryptionService::ProcessOne(
    const ConnectionID &conn,
    ConnectionInfo &info)
{
    LogDebug ("process One");
    RawBuffer response;

    try {
        if (!info.buffer.Ready())
            return false;

        if (info.interfaceID != SOCKET_ID_ENCRYPTION)
            return false;

        response = ProcessEncryption(info.credentials, info.buffer);
        m_serviceManager->Write(conn, response);
        return true;
    } catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
    } catch (const std::exception &e) {
        LogError("Std exception:: " << e.what());
    } catch (...) {
        LogError("Unknown exception. Closing socket.");
    }

    m_serviceManager->Close(conn);
    return false;
}

RawBuffer EncryptionService::ProcessEncryption(const Credentials &/*cred*/, MessageBuffer &buffer)
{
    int command = 0;
    int msgId = 0;
    buffer.Deserialize(command);
    buffer.Deserialize(msgId);
    return MessageBuffer::Serialize(command, msgId, CKM_API_ERROR_SERVER_ERROR).Pop();
}

} /* namespace CKM */
