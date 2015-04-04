/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        data-adapter.h
 * @author      Dongsun Lee(ds73.lee@samsung.com)
 * @version     1.0
 * @brief       Header of data adaptation layer in front of db access
 */

#pragma once

#include <db-row.h>


namespace CKM {

class DataAdapter
{
public:
    DataAdapter();
    virtual ~DataAdapter();

    NONCOPYABLE(DataAdapter);

    /*
     *  It is called just after row(s) is extracted from db and decrypted.
     */
    int afterReadData(DB::Row &row);
    int afterReadData(DB::RowVector &rows);

    /*
     *  It is called just before row is encrypted and saved in db.
     */
    int beforeSaveData(DB::Row &row);
    int beforeSaveData(DB::RowVector &rows);

    /*
     *  It is called just after rows are deleted from db.
     */
    int afterDeleteData(DB::RowVector &rows);
};

}
