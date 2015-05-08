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
 * @file        InitialValuesFile.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValuesFile class implementation.
 */

#include <iostream>
#include <InitialValuesFile.h>
#include <InitialValueHandler.h>
#include <BufferHandler.h>
#include <ObjectType.h>
#include <EncodingType.h>
#include <dpl/log/log.h>

using namespace CKM;

namespace {
const int          XML_CURRENT_VERSION      = 1;
const char * const XML_TAG_INITIAL_VALUES   = "InitialValues";
const char * const XML_TAG_KEY              = "Key";
const char * const XML_TAG_DATA             = "Data";
const char * const XML_TAG_CERT             = "Cert";
const char * const XML_TAG_PEM              = "PEM";
const char * const XML_TAG_DER              = "DER";
const char * const XML_TAG_ASCII            = "ASCII";
const char * const XML_TAG_BASE64           = "Base64";
const char * const XML_TAG_PERMISSION       = "Permission";
const char * const XML_ATTR_VERSION         = "version";
}

InitialValuesFile::InitialValuesFile(const char *XML_filename, CKMLogic * db_logic)
        : m_parser(XML_filename), m_logic(db_logic),
          m_header(std::make_shared<HeaderHandler>(*this))
{
    m_parser.RegisterErrorCb(InitialValuesFile::Error);
    m_parser.RegisterElementCb(XML_TAG_INITIAL_VALUES,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_header;
            },
            [this](const XML::Parser::ElementHandlerPtr &) {});
}

void InitialValuesFile::registerElementListeners()
{
    m_parser.RegisterElementCb(XML_TAG_KEY,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetObjectHandler(ObjectType::KEY);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseObjectHandler(ObjectType::KEY);
            });
    m_parser.RegisterElementCb(XML_TAG_CERT,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetObjectHandler(ObjectType::CERT);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseObjectHandler(ObjectType::CERT);
            });
    m_parser.RegisterElementCb(XML_TAG_DATA,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetObjectHandler(ObjectType::DATA);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseObjectHandler(ObjectType::DATA);
            });

    m_parser.RegisterElementCb(XML_TAG_PEM,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetBufferHandler(EncodingType::PEM);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseBufferHandler(EncodingType::PEM);
            });
    m_parser.RegisterElementCb(XML_TAG_DER,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetBufferHandler(EncodingType::DER);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseBufferHandler(EncodingType::DER);
            });
    m_parser.RegisterElementCb(XML_TAG_ASCII,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetBufferHandler(EncodingType::ASCII);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseBufferHandler(EncodingType::ASCII);
            });
    m_parser.RegisterElementCb(XML_TAG_BASE64,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetBufferHandler(EncodingType::BASE64);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleaseBufferHandler(EncodingType::BASE64);
            });
    m_parser.RegisterElementCb(XML_TAG_PERMISSION,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_logic.GetPermissionHandler();
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_logic.ReleasePermissionHandler();
            });
}

void InitialValuesFile::Error(const XML::Parser::ErrorType errorType,
                              const std::string & log_msg)
{
    switch(errorType)
    {
        case XML::Parser::VALIDATION_ERROR:
            LogWarning("validating error: " << log_msg);
            break;
        case XML::Parser::PARSE_WARNING:
            LogWarning("parsing warning: " << log_msg);
            break;
        case XML::Parser::PARSE_ERROR:
            LogWarning("parsing error: " << log_msg);
            break;
    }
}

int InitialValuesFile::Validate(const char *XSD_file)
{
    return m_parser.Validate(XSD_file);
}

int InitialValuesFile::Parse()
{
    int ec = m_parser.Parse();
    if(!m_header.get()->isCorrectVersion()) {
        LogError("bypassing XML file: " << m_filename << " - wrong file version!");
        ec = XML::Parser::ERROR_INVALID_VERSION;
    }
    return ec;
}



InitialValuesFile::HeaderHandler::HeaderHandler(InitialValuesFile & parent) : m_version(-1), m_parent(parent) {}
void InitialValuesFile::HeaderHandler::Start(const XML::Parser::Attributes & attr)
{
    // get key type
    if(attr.find(XML_ATTR_VERSION) != attr.end())
    {
        m_version = atoi(attr.at(XML_ATTR_VERSION).c_str());

        if(isCorrectVersion())
            m_parent.registerElementListeners();
    }
}
bool InitialValuesFile::HeaderHandler::isCorrectVersion() const {
    return m_version == XML_CURRENT_VERSION;
}
