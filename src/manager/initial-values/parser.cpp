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
std::string tolower(const std::string& s)
{
    std::string retval = s;
    std::transform(retval.begin(), retval.end(), retval.begin(), ::tolower);
    return retval;
}
}

Parser::Parser(const char *XML_filename)
    : m_errorCb(0)
{
    if(XML_filename)
        m_XMLfile = XML_filename;
    memset(&m_saxHandler, 0, sizeof(m_saxHandler));
    m_saxHandler.startDocument = &Parser::StartDocument;
    m_saxHandler.endDocument = &Parser::EndDocument;
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
    if(!XSD_schema)
        return PARSER_ERROR_INVALID_ARGUMENT;

    int retCode;
    xmlSchemaParserCtxtPtr parserCtxt = NULL;
    xmlSchemaPtr schema = NULL;
    xmlSchemaValidCtxtPtr validCtxt = NULL;
    try {
        parserCtxt = xmlSchemaNewParserCtxt(XSD_schema);
        if(parserCtxt == NULL)
            return PARSER_ERROR_INVALID_ARGUMENT;

        schema = xmlSchemaParse(parserCtxt);
        if(schema == NULL)
            return PARSER_ERROR_XSD_PARSE_FAILED;

        validCtxt = xmlSchemaNewValidCtxt(schema);
        if(validCtxt == NULL)
            return PARSER_ERROR_INTERNAL;

        xmlSetStructuredErrorFunc(NULL, NULL);
        xmlSetGenericErrorFunc(this, &Parser::Error);
        xmlThrDefSetStructuredErrorFunc(NULL, NULL);
        xmlThrDefSetGenericErrorFunc(this, &Parser::Error);
        if(0 != xmlSchemaValidateFile(validCtxt, m_XMLfile.c_str(), 0))
            retCode = PARSER_ERROR_XML_VALIDATION_FAILED;
        else
            retCode = PARSER_SUCCESS;
    } catch (const std::bad_alloc &) {
        retCode = PARSER_ERROR_NO_MEMORY;
    } catch (...) {
        retCode = PARSER_ERROR_UNKNOWN;
    }

    if(parserCtxt)
        xmlSchemaFreeParserCtxt(parserCtxt);
    if (schema)
        xmlSchemaFree(schema);
    if (validCtxt)
        xmlSchemaFreeValidCtxt(validCtxt);

    return retCode;
}

int Parser::Parse()
{
    int retCode;
    try {
        if(0 != xmlSAXUserParseFile(&m_saxHandler, this, m_XMLfile.c_str()))
            retCode = PARSER_ERROR_XML_PARSE_FAILED;
        else
            retCode = PARSER_SUCCESS;
    } catch (const std::bad_alloc &) {
        retCode = PARSER_ERROR_NO_MEMORY;
    } catch (...) {
        retCode = PARSER_ERROR_UNKNOWN;
    }

    return retCode;
}

int Parser::RegisterErrorCb(const ErrorCb newCb)
{
    if(m_errorCb)
        return PARSER_ERROR_CALLBACK_PRESENT;
    m_errorCb = newCb;
    return PARSER_SUCCESS;
}

int Parser::RegisterElementCb(const char * elementName,
                              const StartCb startCb,
                              const EndCb endCb)
{
    if(!elementName)
        return PARSER_ERROR_INVALID_ARGUMENT;

    std::string key = tolower(elementName);

    if(m_elementListenerMap.find(elementName) != m_elementListenerMap.end())
        return PARSER_ERROR_CALLBACK_PRESENT;

    m_elementListenerMap[key] = {startCb, endCb};
    return PARSER_SUCCESS;
}

void Parser::StartDocument()
{
}

void Parser::EndDocument()
{
}

void Parser::StartElement(const xmlChar *name,
                          const xmlChar **attrs)
{
    std::string key = tolower(reinterpret_cast<const char*>(name));
    if(m_elementListenerMap.find(key) == m_elementListenerMap.end())
        return;

    const ElementListener & current = m_elementListenerMap[key];
    if( !current.startCb )
        return;

    Attributes attribs;
    {
        size_t numAttrs = 0;
        std::vector<std::string> keys, values;
        while(attrs && attrs[numAttrs])
        {
            const char *attrChr = reinterpret_cast<const char*>(attrs[numAttrs]);
            if((numAttrs%2)==0)
                keys.push_back(attrChr);
            else
                values.push_back(attrChr);
            numAttrs ++;
        }
        std::transform(keys.begin(), keys.end(),
                       values.begin(),
                       std::inserter(attribs, attribs.end()),
                       [](const std::string &key, const std::string &val)
                       {
                           return std::make_pair(key, val);
                       });
    }

    ElementHandlerPtr newHandler = current.startCb();
    m_elementHandlerStack.push(newHandler);

    newHandler->Start(attribs);
}

void Parser::EndElement(const xmlChar *name)
{
    std::string key = tolower(reinterpret_cast<const char*>(name));
    if(m_elementListenerMap.find(key) == m_elementListenerMap.end())
        return;

    const ElementListener & current = m_elementListenerMap[key];
    if( !current.endCb )
        return;

    if( !m_elementHandlerStack.empty() )
    {
        ElementHandlerPtr &currentHandler = m_elementHandlerStack.top();
        currentHandler.get()->End();
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
        currentHandler.get()->Characters(chars);
    }
}

void Parser::Error(const errorLogLevel logLevel,
                   const std::string & logMsg)
{
    if(m_errorCb)
        m_errorCb(logLevel, logMsg);
}

//
// -------------------------- start of static wrappers --------------------------
//

void Parser::StartDocument(void *userData)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    parser.StartDocument();
}
void Parser::EndDocument(void *userData)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    parser.EndDocument();
}
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

void Parser::Error(void *userData,
                   const char *msg,
                   ...)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    char msg_buf[512];
    va_list args;
    va_start(args, msg);
    vsnprintf(msg_buf, sizeof(msg_buf), msg, args);
    va_end(args);
    parser.Error(LOG_LEVEL_ERROR, trim(std::string(msg_buf)));
}

void Parser::Warning(void *userData,
                     const char *msg,
                     ...)
{
    Parser &parser = *(static_cast<Parser *>(userData));
    char msg_buf[512];
    va_list args;
    va_start(args, msg);
    vsnprintf(msg_buf, sizeof(msg_buf), msg, args);
    va_end(args);
    parser.Error(LOG_LEVEL_WARNING, trim(std::string(msg_buf)));
}
//
// -------------------------- end of static wrappers --------------------------
//
