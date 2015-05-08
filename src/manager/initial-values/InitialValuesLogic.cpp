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
 * @file        InitialValuesLogic.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValuesLogic class implementation.
 */

#include <memory>
#include <InitialValuesLogic.h>
#include <InitialValueHandler.h>
#include <KeyHandler.h>
#include <CertHandler.h>
#include <DataHandler.h>
#include <ObjectType.h>
#include <EncodingType.h>

using namespace CKM;

XML::Parser::ElementHandlerPtr InitialValuesLogic::GetObjectHandler(ObjectType type)
{
    switch(type)
    {
        case KEY:
            m_currentHandler = std::make_shared<KeyHandler>(m_db_logic);
            break;

        case CERT:
            m_currentHandler = std::make_shared<CertHandler>(m_db_logic);
            break;

        case DATA:
            m_currentHandler = std::make_shared<DataHandler>(m_db_logic);
            break;

        default:
            m_currentHandler.reset();
            break;
    }

    return m_currentHandler;
}

void InitialValuesLogic::ReleaseObjectHandler(ObjectType /*type*/)
{
    m_currentHandler.reset();
}




XML::Parser::ElementHandlerPtr InitialValuesLogic::GetBufferHandler(EncodingType type)
{
    if( !m_currentHandler.get() )
        return XML::Parser::ElementHandlerPtr();

    return m_currentHandler.get()->CreateBufferHandler(type);
}
void InitialValuesLogic::ReleaseBufferHandler(EncodingType /*type*/)
{
}


XML::Parser::ElementHandlerPtr InitialValuesLogic::GetPermissionHandler()
{
    if( !m_currentHandler.get() )
        return XML::Parser::ElementHandlerPtr();

    return m_currentHandler.get()->CreatePermissionHandler();
}
void InitialValuesLogic::ReleasePermissionHandler()
{
}
