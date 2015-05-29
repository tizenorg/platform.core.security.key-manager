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

#include <stdexcept>
#include <utility>
#include <encryption-service.h>
#include <protocols.h>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <crypto-request.h>

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

void EncryptionService::RespondToClient(const CryptoRequest& request,
                                        int retCode,
                                        const RawBuffer& data)
{
    // TODO exceptions
    RawBuffer response = MessageBuffer::Serialize(
            static_cast<int>(request.command), request.msgId, retCode, data).Pop();
    m_serviceManager->Write(request.conn, response);
}

void EncryptionService::RequestKey(const Credentials& /*cred*/,
                                   const Alias& /*alias*/,
                                   const Label& /*label*/)
{
    // TODO
    throw std::runtime_error("Not supported");
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
    try {
        if (!info.buffer.Ready())
            return false;

        if (info.interfaceID != SOCKET_ID_ENCRYPTION)
            return false;

        ProcessEncryption(conn, info.credentials, info.buffer);
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

EncryptionLogic& EncryptionService::Logic()
{
    if (!m_logic)
        m_logic.reset(new EncryptionLogic(*this));

    return *m_logic;
}

void EncryptionService::ProcessEncryption(const ConnectionID &conn,
                                          const Credentials &cred,
                                          MessageBuffer &buffer)
{
    EncryptionCommand command;
    int tmpCmd = 0;
    int msgId = 0;
    CryptoAlgorithmSerializable cas;
    Name name;
    Label label;
    Password password;
    RawBuffer input;
    RawBuffer output;
    buffer.Deserialize(tmpCmd, msgId, cas, name, label, password, input);
    command = static_cast<EncryptionCommand>(tmpCmd);
    if (command != EncryptionCommand::ENCRYPT && command != EncryptionCommand::DECRYPT)
        throw std::runtime_error("Unsupported command: " + tmpCmd);

    CryptoRequest req = {
            conn,
            cred,
            command,
            msgId,
            cas,
            std::move(name),
            std::move(label),
            std::move(password),
            std::move(input) };
    Logic().crypt(req);
}

} /* namespace CKM */
