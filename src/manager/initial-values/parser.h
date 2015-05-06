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
 * @file        parser.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       XML parser class.
 */

#ifndef XML_PARSER_H_
#define XML_PARSER_H_

#include <map>
#include <vector>
#include <string>
#include <stack>
#include <functional>
#include <memory>
#include <libxml/parser.h>
#include <libxml/tree.h>

namespace XML
{

class Parser
{
    public:
        static const int PARSER_SUCCESS                        =   0;
        static const int PARSER_ERROR_UNKNOWN                  =   -1000;
        static const int PARSER_ERROR_XML_VALIDATION_FAILED    =   -1001;
        static const int PARSER_ERROR_XSD_PARSE_FAILED         =   -1002;
        static const int PARSER_ERROR_XML_PARSE_FAILED         =   -1003;
        static const int PARSER_ERROR_INVALID_ARGUMENT         =   -1004;
        static const int PARSER_ERROR_CALLBACK_PRESENT         =   -1005;
        static const int PARSER_ERROR_INTERNAL                 =   -1006;
        static const int PARSER_ERROR_NO_MEMORY                =   -1007;

        Parser(const char *XML_filename);
        /*virtual*/ ~Parser();

        int Validate(const char *XSD_schema);
        int Parse();

        // handling error messages
        enum errorLogLevel {
            LOG_LEVEL_ERROR,
            LOG_LEVEL_WARNING
        };
        typedef std::function<void (const errorLogLevel, const std::string &)> ErrorCb;
        int RegisterErrorCb(const ErrorCb newCb);

        typedef std::map<std::string, std::string> Attributes;
        class ElementHandler
        {
            public:
                virtual ~ElementHandler() {}
                virtual void Start(const Attributes &) = 0;
                virtual void Characters(const std::string & data) = 0;
                virtual void End() = 0;
        };
        class EmptyHandler : public ElementHandler
        {
            public:
                virtual ~EmptyHandler() {};

                virtual void Start(const XML::Parser::Attributes &) {};
                virtual void Characters(const std::string &) {};
                virtual void End() {};
        };
        typedef std::shared_ptr<ElementHandler> ElementHandlerPtr;

        typedef std::function<ElementHandlerPtr ()> StartCb;
        typedef std::function<void (const ElementHandlerPtr &)> EndCb;
        int RegisterElementCb(const char * elementName,
                              const StartCb startCb,
                              const EndCb endCb);

    protected:
        void StartDocument();
        void EndDocument();
        void StartElement(const xmlChar *name,
                          const xmlChar **attrs);
        void EndElement(const xmlChar *name);
        void Characters(const xmlChar *ch, size_t chLen);
        void Error(const errorLogLevel logLevel,
                   const std::string & logMsg);

    private:
        static void StartDocument(void *userData);
        static void EndDocument(void *userData);
        static void StartElement(void *userData,
                                 const xmlChar *name,
                                 const xmlChar **attrs);
        static void EndElement(void *userData,
                               const xmlChar *name);
        static void Characters(void *userData,
                               const xmlChar *ch,
                               int len);
        static void Error(void *userData,
                          const char *msg,
                          ...);
        static void Warning(void *userData,
                            const char *msg,
                            ...);

    private:
        xmlSAXHandler           m_saxHandler;
        std::string             m_XMLfile;
        ErrorCb                 m_errorCb;

        struct ElementListener
        {
            StartCb     startCb;
            EndCb       endCb;
        };
        std::map<std::string, ElementListener> m_elementListenerMap;
        std::stack<ElementHandlerPtr> m_elementHandlerStack;
};

}
#endif /* XML_PARSER_H_ */
