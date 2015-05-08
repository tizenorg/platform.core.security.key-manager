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
 * @file        KeyHandler.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       KeyHandler class.
 */

#ifndef KEYHANDLER_H_
#define KEYHANDLER_H_

#include <parser.h>
#include <InitialValueHandler.h>

namespace CKM
{

class KeyHandler : public InitialValueHandler
{
public:
    KeyHandler() : m_keyType(UNKNOWN) {}
    virtual ~KeyHandler();

    enum Type { // TODO replace with CKM constant
        UNKNOWN,
        RSA_PUB,
        RSA_PRIV,
        DSA_PUB,
        DSA_PRIV,
        ECDSA_PRIV,
        ECDSA_PUB,
        AES
    };
    virtual void Start(const XML::Parser::Attributes &);
    virtual void Characters(const std::string & data);
    virtual void End();

protected:
    static KeyHandler::Type parseType(const std::string & typeStr);

    KeyHandler::Type m_keyType;
};

}
#endif /* KEYHANDLER_H_ */
