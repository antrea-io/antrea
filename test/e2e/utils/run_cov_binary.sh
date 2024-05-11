#!/usr/bin/env bash

# Copyright 2024 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is meant to wrap a coverage instrumented binary.
# When the main process is killed, the script will start sleeping until a signal
# is received, providing the opportunity for the user to retrieve code coverage
# files.

set -euo pipefail

TEST_PID=

function quit {
    echo "Received signal, exiting"
    # While not strictly required, it is better to try to terminate the test process gracefully if it is still running.
    if [ "$TEST_PID" != "" ]; then
        echo "Sending signal to test process"
        kill -SIGTERM $TEST_PID > /dev/null 2>&1 || true
        wait $TEST_PID
        echo "Test process exited gracefully"
    fi
    exit 0
}

# This is necessary: without an explicit signal handler, the SIGTERM signal will be discarded when running
# as a process with PID 1 in a container.
trap 'quit' SIGTERM

# Run the test process in the background, to allow exiting when a signal is received.
"$@" &
TEST_PID=$!
wait $TEST_PID
TEST_PID=

# Sleep in the background, to allow exiting as soon as a signal is received.
sleep infinity & wait
