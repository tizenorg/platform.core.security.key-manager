/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        data-adapter.cpp
 * @author      Dongsun Lee(ds73.lee@samsung.com)
 * @version     1.0
 * @brief       dummy data-adapter implementation.
 */
#include <dpl/log/log.h>
#include <ckm/ckm-error.h>
#include <data-adapter.h>

namespace CKM {


DataAdapter::DataAdapter() { }

DataAdapter::~DataAdapter() { }


int DataAdapter::afterReadData(DB::Row &row)
{
	LogDebug("DataAdapter::afterReadData - No Adaptation Version: " 
                << "Row[" << row.ownerLabel<< "," << row.name << "]"
                << "inExternal= " << row.inExternal 
                << ", dataType=" << row.dataType <<", size=" << row.dataSize);
	return CKM_API_SUCCESS;
}

int DataAdapter::afterReadData(DB::RowVector &rows)
{
    for(auto &i: rows)
        afterReadData(i);
	return CKM_API_SUCCESS;
}

int DataAdapter::beforeSaveData(DB::Row &row)
{
	LogDebug("DataAdapter::beforeSaveData- No Adaptation Version: " 
                << "Row[" << row.ownerLabel<< "," << row.name << "]" 
                << "inExternal= " << row.inExternal 
                << ", dataType=" << row.dataType <<", size=" << row.dataSize);
    return CKM_API_SUCCESS;
}

int DataAdapter::beforeSaveData(DB::RowVector &rows)
{
    for(auto &i: rows)
        beforeSaveData(i);
    return CKM_API_SUCCESS;
}

int DataAdapter::afterDeleteData(DB::RowVector &rows)
{
    for(auto &i: rows) {
        LogDebug("DataAdapter::afterDeleteData- No Adaptation Version: "
                << "Row[" << i.ownerLabel<< "," << i.name << "]" 
                << "inExternal= " << i.inExternal 
                << ", dataType=" << i.dataType <<", size=" << i.dataSize);
    }
    return CKM_API_SUCCESS;
}


}
