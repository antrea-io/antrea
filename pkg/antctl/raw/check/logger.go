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

package check

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

type Logger struct {
	prefix string
}

func NewLogger(prefix string) Logger {
	return Logger{
		prefix: prefix,
	}
}

type stringFormatterFunc func(format string, a ...interface{}) string

func noopStringFormatter(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

func (l Logger) log(stringFormatter stringFormatterFunc, format string, a ...interface{}) {
	fmt.Fprint(os.Stdout, l.prefix)
	fmt.Fprintln(os.Stdout, stringFormatter(format, a...))
}

func (l Logger) Log(format string, a ...interface{}) {
	l.log(noopStringFormatter, format, a...)
}

func (l Logger) Success(format string, a ...interface{}) {
	l.log(color.GreenString, format, a...)
}

func (l Logger) Fail(format string, a ...interface{}) {
	l.log(color.RedString, format, a...)
}

func (l Logger) Warning(format string, a ...interface{}) {
	l.log(color.YellowString, format, a...)
}
