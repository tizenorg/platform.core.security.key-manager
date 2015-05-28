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
 * @file       ckmc-params.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <ckmc-params.h>

#include <map>

namespace {

typedef std::map<ckmc_param_name_e, ParamType> ParamTypeMap;

ParamTypeMap g_paramTypeMap = {
        { CKMC_PARAM_ALGO_TYPE,     INTEGER },

        { CKMC_PARAM_ED_IV,         BUFFER},
        { CKMC_PARAM_ED_CTR_LEN,    INTEGER},
        { CKMC_PARAM_ED_AAD,        BUFFER},
        { CKMC_PARAM_ED_TAG_LEN,    INTEGER},
        { CKMC_PARAM_ED_LABEL,      BUFFER},

        { CKMC_PARAM_GEN_KEY_LEN,   INTEGER},
        { CKMC_PARAM_GEN_EC,        INTEGER},

        { CKMC_PARAM_SV_HASH_ALGO,  INTEGER},
        { CKMC_PARAM_SV_RSA_PADDING,INTEGER},
};

} // namespace anonymous

ParamType getParamType(ckmc_param_name_e name)
{
    return g_paramTypeMap.at(name);
}
