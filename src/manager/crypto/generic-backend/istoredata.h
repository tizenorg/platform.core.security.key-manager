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
 * @file       istoredata.h
 * @author     Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version    1.0
 */
#pragma once

#include <ckm/ckm-type.h>
#include <data-type.h>

namespace CKM {
namespace Crypto {

class IStoreData {
public:
    virtual ~IStoreData() {};

    virtual const CKM::DataType getType() const = 0;
    virtual const CKM::RawBuffer & getData() const = 0;
};

class IStoreDataEncryption
{
public:
    virtual ~IStoreDataEncryption() {};
    virtual const CKM::RawBuffer & getEncryptedKey() const = 0;
    virtual const CKM::RawBuffer & getEncryptionIV() const = 0;
};

} // namespace Crypto
} // namespace CKM
