#!/bin/bash

USER_NAME=key-manager
GROUP_NAME=key-manager
CKM_DATA_PATH="`tzplatform-get TZ_SYS_DATA | cut -d'=' -f2`/ckm"
SMACK_LABEL=System

id -g $GROUP_NAME > /dev/null 2>&1
if [ $? -eq 1 ]; then
    groupadd $GROUP_NAME -r > /dev/null 2>&1
fi

id -u $USER_NAME > /dev/null 2>&1
if [ $? -eq 1 ]; then
    useradd -d /var/lib/empty -s /sbin/nologin -r -g $GROUP_NAME $USER_NAME > /dev/null 2>&1
fi

# In ckm version <= 0.1.18 all files were owned by root.
find ${CKM_DATA_PATH} -exec chsmack -a $SMACK_LABEL {} \;
chown ${USER_NAME}:${GROUP_NAME} -R ${CKM_DATA_PATH}

