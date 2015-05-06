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
 * @file        parser.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       XML parser class implementation.
 */

#include <string>
#include <string.h>
#include <algorithm>
#include <libxml/parser.h>
#include <libxml/valid.h>
#include <libxml/xmlschemas.h>
#include <parser.h>
#include <dpl/log/log.h>

using namespace XML;

namespace
{
const char * const WHITESPACE = " \n\r\t";
std::string trim_left(const std::string& s)
{
    size_t startpos = s.find_first_not_of(WHITESPACE);
    return (startpos == std::string::npos) ? "" : s.substr(startpos);
}

std::string trim_right(const std::string& s)
{
    size_t endpos = s.find_last_not_of(WHITESPACE);
    return (endpos == std::string::npos) ? "" : s.substr(0, endpos+1);
}
std::string trim(const std::string& s)
{
    return trim_right(trim_left(s));
}
}

Parser::Parser(const char *XML_filename)
    : m_errorCb(0)
{
    if(XML_filename)
        m_XMLfile = XML_filename;
    memset(&m_saxHandler, 0, sizeof(m_saxHandler));
    m_saxHandler.startElement = &Parser::StartElement;
    m_saxHandler.endElement = &Parser::EndElement;
    m_saxHandler.characters = &Parser::Characters;
    m_saxHandler.error = &Parser::Error;
    m_saxHandler.warning = &Parser::Warning;
}
Parser::~Parser()
{
    xmlCleanupParser();
}

int Parser::Validate(const char *XSD_schema)
{
    if(!XSD_schema) {
        LogError("no XSD file path given");
        return ERROR_INVALID_ARGUMENT;
    }

    int retCode;
    std::unique_ptr<xmlSchemaParserCtxt, void(*)(xmlSchemaParserCtxtPtr)>
            parserCtxt(xmlSchemaNewParserCtxt(XSD_schema),
                       [](xmlSchemaParserCtxtPtr ctx){ xmlSchemaFreeParserCtxt(ctx); });
    if(!parserCtxt) {
        LogError("XSD file path is invalid");
        return ERROR_INVALID_ARGUMENT;
    }

    std::unique_ptr<xmlSchema, void(*)(xmlSchemaPtr)>
        schema(xmlSchemaParse(parserCtxt.get()),
                       [](xmlSchemaPtr schemaPtr){ xmlSchemaFree(schemaPtr); });
    if(!schema) {
        LogError("Parsing XSD file failed");
        return ERROR_XSD_PARSE_FAILED;
    }


    std::unique_ptr<xmlSchemaValidCtxt, void(*)(xmlSchemaValidCtxtPtr)>
        validCtxt(xmlSchemaNewValidCtxt(schema.get()),
                       [](xmlSchemaValidCtxtPtr validCtxPtr){ xmlSchemaFreeValidCtxt(validCtxPtr); });
    if(!validCtxt) {
        LogError("Internal parser error");
        return ERROR_INTERNAL;
    }

    xmlSetStructuredErrorFunc(NULL, NULL);
    xmlSetGenericErrorFunc(this, &Parser::ErrorValidate);
    xmlThrDefSetStructuredErrorFunc(NULL, NULL);
    xmlThrDefSetGenericErrorFunc(this, &Parser::ErrorValidate);

    retCode = xmlSchemaValidateFile(validCtxt.get(), m_XMLfile.c_str(), 0);
    if(0 != retCode) {
        LogWarning("Validating XML file failed, ec: " << retCode);
        retCode = ERROR_XML_VALIDATION_FAILED;
    }
    else
        retCode = SUCCESS;

    return retCode;
}

int Parser::Parse()
{
    int retCode = xmlSAXUserParseFile(&m_saxHandler, this, m_XMLfile.c_str());
    if(0 != retCode) {
        LogWarning("Parsing XML file failed, ec: " << retCode);
        retCode = ERROR_XML_PARSE_FAILED;
    }
    else
        retCode = SUCCESS;

    return retCode;
}

int Parser::RegisterErrorCb(const ErrorCb newCb)
{
    if(m_errorCb) {
        LogError("Callback already registered!");
        return ERROR_CALLBACK_PRESENT;
    }
    m_errorCb = newCb;
    return SUCCESS;
}

int Parser::RegisterElementCb(const char * elementName,
                              const StartCb startCb,
                              const EndCb endCb)
{
    if(!elementName)
        return ERROR_INVALID_ARGUMENT;

    std::string key(elementName);

    if(m_elementListenerMap.find(elementName) != m_elementListenerMap.end()) {
        LogError("Callback for element " << elementName << " already registered!");
        return ERROR_CALLBACK_PRESENT;
    }

    m_elementListenerMap[key] = {startCb, endCb};
    return SUCCESS;
}

void Parser::StartElement(const xmlChar *name,
                          const xmlChar **attrs)
{
    std::string key(reinterpret_cast<const char*>(name));
    if(m_elementListenerMap.find(key) == m_elementListenerMap.end())
        return;

    ElementHandlerPtr newHandler;
    const ElementListener & current = m_elementListenerMap[key];
    if(current.startCb)
    {
        Attributes attribs;
        {
            size_t numAttrs = 0;
            std::string key;
            while(attrs && attrs[numAttrs])
            {
                const char *attrChr = reinterpret_cast<const char*>(attrs[numAttrs]);
                if((numAttrs%2)==0)
                    key = std::string(attrChr);
                else
                    attribs[key] = std::string(attrChr);
                numAttrs ++;
            }
        }

        ElementHandlerPtr newHandler = current.startCb();
        if(newHandler)
            newHandler->Start(attribs);
    }
    m_elementHandlerStack.push(newHandler);
}

void Parser::EndElement(const xmlChar *name)
{
    std::string key(reinterpret_cast<const char*>(name));
    if(m_elementListenerMap.find(key) == m_elementListenerMap.end())
        return;

    if( !m_elementHandlerStack.empty() )
    {
        ElementHandlerPtr &currentHandler = m_elementHandlerStack.top();
        if(currentHandler)
            currentHandler.get()->End();

        const ElementListener & current = m_elementListenerMap[key];
        if(current.endCb)
            current.endCb(currentHandler);

        m_elementHandlerStack.pop();
    }
}

void Parser::Characters(const xmlChar *ch, size_t chLen)
{
    std::string chars = trim(std::string(reinterpret_cast<const char*>(ch), chLen));
    if(chars.empty())
        return;

    if( !m_elementHandlerStack.empty() )
    {
        ElementHandlerPtr &currentHandler = m_elementHandlerStack.top();
        if(currentHandler)
            currentHandler.get()->Characters(chars);
    }
}

void Parser::Error(const ErrorType errorType, const char *msg, va_list &args)
{
    if(m_errorCb)
    {
        va_list args2;
        va_copy(args2, args);
        std::vector<char> buf(1 + std::vsnprintf(NULL, 0, msg, args));
        std::vsnprintf(buf.data(), buf.size(), msg, args2);
        va_end(args2);
        m_errorCb(errorType, trim(std::string(buf.begin(), buf.end())));
    }
}

//
// -------------------------- start of static wrappers --------------------------
//

void Parser::StartElement(void *userData,
                          const xmlChar *name,
                          const xmlChar **attrs)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    parser.StartElement(name, attrs);
}
void Parser::EndElement(void *userData,
                        const xmlChar *name)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    parser.EndElement(name);
}
void Parser::Characters(void *userData,
                        const xmlChar *ch,
                        int len)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    parser.Characters(ch, static_cast<size_t>(len));
}

void Parser::ErrorValidate(void *userData,
                           const char *msg,
                           ...)
{
    va_list args;
    va_start(args, msg);
    Parser *parser = static_cast<Parser *>(userData);
    parser->Error(VALIDATION_ERROR, msg, args);
    va_end(args);
}

void Parser::Error(void *userData,
                   const char *msg,
                   ...)
{
    va_list args;
    va_start(args, msg);
    Parser *parser = static_cast<Parser *>(userData);
    parser->Error(PARSE_ERROR, msg, args);
    va_end(args);
}

void Parser::Warning(void *userData,
                     const char *msg,
                     ...)
{
    va_list args;
    va_start(args, msg);
    Parser &parser = *(static_cast<Parser *>(userData));
    parser.Error(PARSE_WARNING, msg, args);
    va_end(args);
}
//
// -------------------------- end of static wrappers --------------------------
//
