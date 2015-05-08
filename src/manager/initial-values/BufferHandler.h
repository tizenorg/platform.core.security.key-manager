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
 * @file        BufferHandler.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       BufferHandler class.
 */

#ifndef BUFFERHANDLER_H_
#define BUFFERHANDLER_H_

#include <parser.h>
#include <EncodingType.h>

namespace CKM
{

class BufferHandler : public XML::Parser::ElementHandler
{
public:
    typedef std::shared_ptr<BufferHandler> BufferHandlerPtr;

    BufferHandler(EncodingType type);
    virtual ~BufferHandler();

    virtual void Start(const XML::Parser::Attributes &);
    virtual void Characters(const std::string & data);
    virtual void End();

private:
    EncodingType    m_encoding;
    std::string     m_data;
};

}
#endif /* BUFFERHANDLER_H_ */
