/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        key-impl.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Key implementation.
 */
#pragma once

#include <memory>

#include <ckm/ckm-type.h>
#include <ckm/ckm-key.h>
#include <openssl/evp.h>
#include <symbol-visibility.h>

namespace CKM {

class COMMON_API KeyImpl : public Key {
  public:
	typedef std::shared_ptr<EVP_PKEY> EvpShPtr;

	KeyImpl();
	KeyImpl(const KeyImpl &second) = delete;
	KeyImpl &operator=(const KeyImpl &second) = delete;
	KeyImpl(const RawBuffer &buffer, const Password &password = Password());
	KeyImpl(EvpShPtr pkey, KeyType type);

	virtual KeyType getType() const;
	virtual RawBuffer getDER() const;
	virtual RawBuffer getDERPUB() const;
	virtual RawBuffer getDERPRV() const;
	virtual EvpShPtr getEvpShPtr() const;
	/* //TODO
	virtual ElipticCurve getCurve() const
	{
	    return ElipticCurve::prime192v1;
	}
	*/

	virtual int getSize() const {
		// TODO
		return 0;
	}

	virtual bool empty() const;
	virtual ~KeyImpl() {}

  protected:
	EvpShPtr m_pkey;
	KeyType m_type;
};

} // namespace CKM

