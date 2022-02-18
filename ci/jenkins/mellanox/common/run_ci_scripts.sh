#!/bin/bash -x
# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

status=0
echo "I am" $(whoami)
env

cd $WORKSPACE/

TMP_WORKSPACE=/tmp/k8s_$$

WORKSPACE=${TMP_WORKSPACE} $WORKSPACE/scripts/stop_ci.sh

WORKSPACE=${TMP_WORKSPACE} $WORKSPACE/scripts/start_ci.sh

let status=status+$?
if [[ $status -eq 0 ]]; then
    sleep 120
    WORKSPACE=${TMP_WORKSPACE} $WORKSPACE/scripts/test.sh
    let status=status+$?
else
    echo "ERROR!! Failed to start the CI!!"
fi

WORKSPACE=${TMP_WORKSPACE} $WORKSPACE/scripts/stop_ci.sh

echo "Saving logs"
UPLOAD_LOGPATH=${JOB_NAME}/${BUILD_NUMBER}
mkdir -p ${TMP_WORKSPACE}/${UPLOAD_LOGPATH}
mv $(ls /tmp/*.log |grep kube) ${TMP_WORKSPACE}/logs
mv ${TMP_WORKSPACE}/artifacts ${TMP_WORKSPACE}/logs ${TMP_WORKSPACE}/${UPLOAD_LOGPATH}
gzip -9 -r ${TMP_WORKSPACE}/${UPLOAD_LOGPATH} 2>&1|tee > /dev/null
target=/var/www/html/${UPLOAD_LOGPATH}
ssh $LOGSERVER mkdir -p ${target}
scp -r ${TMP_WORKSPACE}/${UPLOAD_LOGPATH}/* $LOGSERVER:$target 2>&1 | tee > /dev/null

echo ""
echo "Further Logs can be found at: http://$EXT_SERVER/${UPLOAD_LOGPATH}"
echo ""

rm -rf ${TMP_WORKSPACE}
exit $status
