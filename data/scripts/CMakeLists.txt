# Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author      Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
# @brief
#

CONFIGURE_FILE(230.key-manager-change-data-dir.patch.sh.in
               230.key-manager-change-data-dir.patch.sh
               @ONLY)

CONFIGURE_FILE(231.key-manager-migrate-dkek.patch.sh.in
               231.key-manager-migrate-dkek.patch.sh
               @ONLY)

CONFIGURE_FILE(232.key-manager-change-user.patch.sh.in
               232.key-manager-change-user.patch.sh
               @ONLY)

CONFIGURE_FILE(233.key-manager-move-ss-migratable-data.patch.sh.in
               233.key-manager-move-ss-migratable-data.patch.sh
               @ONLY)

INSTALL(FILES
        230.key-manager-change-data-dir.patch.sh
        231.key-manager-migrate-dkek.patch.sh
        232.key-manager-change-user.patch.sh
        233.key-manager-move-ss-migratable-data.patch.sh
    DESTINATION ${RO_ETC_DIR}/opt/upgrade
    PERMISSIONS
        OWNER_READ
        OWNER_WRITE
        OWNER_EXECUTE)

INSTALL(FILES
        create_schema.sql
        drop_all.sql
        migrate_1.sql
        migrate_2.sql
        migrate_3.sql
    DESTINATION ${RO_DATA_DIR}/scripts)
