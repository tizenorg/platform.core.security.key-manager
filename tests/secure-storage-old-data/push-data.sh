#!/bin/bash

SS_BASE_PATH="/opt/share/secure-storage"

sdb root on

sdb shell rm -rf ${SS_BASE_PATH}

sdb shell mkdir -p ${SS_BASE_PATH}

sdb shell mkdir -p ${SS_BASE_PATH}/secure-storage
sdb shell mkdir -p ${SS_BASE_PATH}/secure-storage\:\:test1
sdb shell mkdir -p ${SS_BASE_PATH}/secure-storage\:\:test2

sdb push ./secure-storage/salt ${SS_BASE_PATH}/secure-storage/
sdb push ./secure-storage\:\:test1/test-data-1 ${SS_BASE_PATH}/secure-storage\:\:test1/
sdb push ./secure-storage\:\:test1/test-data-2 ${SS_BASE_PATH}/secure-storage\:\:test1/
sdb push ./secure-storage\:\:test1/test-data-3 ${SS_BASE_PATH}/secure-storage\:\:test1/
sdb push ./secure-storage\:\:test2/test-data-1 ${SS_BASE_PATH}/secure-storage\:\:test2/
sdb push ./secure-storage\:\:test2/test-data-2 ${SS_BASE_PATH}/secure-storage\:\:test2/
sdb push ./secure-storage\:\:test2/test-data-3 ${SS_BASE_PATH}/secure-storage\:\:test2/
