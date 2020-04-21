// Copyright 2020 Antrea Authors
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

package openflow

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

type klogFormatter struct{}

// Format formats logrus log in compliance with k8s log.
func (f *klogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	filePath := entry.Caller.File
	filePathArray := strings.Split(filePath, "/")
	fileName := filePathArray[len(filePathArray)-1]
	pidString := strconv.Itoa(os.Getpid())

	// logrus has seven logging levels: Trace, Debug, Info, Warning, Error, Fatal and Panic.
	b.WriteString(strings.ToUpper(entry.Level.String()[:1]))
	b.WriteString(entry.Time.Format("0102 15:04:05.000000"))
	b.WriteString(" ")
	for i := 0; i < (7 - len(pidString)); i++ {
		b.WriteString(" ")
	}
	b.WriteString(pidString)
	b.WriteString(" ")
	b.WriteString(fileName)
	b.WriteString(":")
	fmt.Fprint(b, entry.Caller.Line)
	b.WriteString("] ")
	if entry.Message != "" {
		b.WriteString(entry.Message)
	}
	b.WriteByte('\n')

	return b.Bytes(), nil
}

func init() {
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&klogFormatter{})
}
