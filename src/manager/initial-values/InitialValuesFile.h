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
 * @file        InitialValuesFile.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValuesFile class.
 */

#ifndef INITIALVALUESFILE_H_
#define INITIALVALUESFILE_H_

#include <parser.h>
#include <InitialValuesLogic.h>
#include <ckm-logic.h>

namespace CKM
{

class InitialValuesFile
{
public:
    InitialValuesFile(const char *XML_filename,
                      CKMLogic * db_logic);

    int Validate(const char *XSD_file);
    int Parse();

private:
    std::string m_filename;
    XML::Parser m_parser;
    InitialValuesLogic m_logic;

    class HeaderHandler : public XML::Parser::ElementHandler
    {
    public:
        HeaderHandler(InitialValuesFile & parent);
        virtual void Start(const XML::Parser::Attributes & attr);
        virtual void Characters(const std::string &) {};
        virtual void End() {};

        bool isCorrectVersion() const;

    private:
        int m_version;
        InitialValuesFile & m_parent;
    };
    typedef std::shared_ptr<HeaderHandler> HeaderHandlerPtr;
    HeaderHandlerPtr m_header;

    void registerElementListeners();
    static void Error(const XML::Parser::ErrorType errorType,
                      const std::string & logMsg);

};

}
#endif /* INITIALVALUESFILE_H_ */
