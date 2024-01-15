// Copyright 2024 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client_pod

import (
	"fmt"
	"testing"
)

func TestCmd(t *testing.T) {
	fmt.Printf("server=%s; output_file=\"ping_log.txt\"; if [ ! -e \"$output_file\" ]; then touch \"$output_file\"; fi; last_status=\"unknown\"; last_change_time=$(date +%%s); while true; do current_time=$(date +%%s); time_diff=$((current_time - last_change_time)); status=$(nc -vz -w 1 \"$server\" %s > /dev/null && echo \"up\" || echo \"down\"); if [ \"$status\" != \"$last_status\" ]; then echo \"$(date) Status changed from $last_status to $status after ${time_diff} seconds\"; echo \"$(date) Status changed from $last_status to $status after ${time_diff} seconds\" >> \"$output_file\"; last_change_time=$current_time; last_status=$status; fi; sleep 0.1; done\n", "127.0.0.1", "80")
}
