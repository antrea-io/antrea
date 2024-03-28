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

set -x

"$@"

while true; do
    # Sleep in the background, to allow exiting as soon as a signal is received
    sleep 5 & wait $!
done
