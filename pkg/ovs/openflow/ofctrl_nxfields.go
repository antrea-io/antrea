// Copyright 2021 Antrea Authors
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

import "fmt"

func (f *RegField) GetRegID() int {
	return f.regID
}

func (f *RegField) GetRange() *Range {
	return f.rng
}

func (f *RegField) GetNXFieldName() string {
	return fmt.Sprintf("%s%d", NxmFieldReg, f.regID)
}

func (f *RegField) GetName() string {
	return f.name
}

func (f *RegField) isFullRange() bool {
	return f.rng.Length() == 32
}

func NewRegField(id int, start, end uint32, name string) *RegField {
	return &RegField{regID: id, rng: &Range{start, end}, name: name}
}

func NewOneBitRegMark(id int, bit uint32, name string) *RegMark {
	field := NewRegField(id, bit, bit, name)
	return &RegMark{value: 1, field: field}
}

func NewOneBitZeroRegMark(id int, bit uint32, name string) *RegMark {
	field := NewRegField(id, bit, bit, name)
	return &RegMark{value: 0, field: field}
}

func NewRegMark(field *RegField, value uint32) *RegMark {
	return &RegMark{value: value, field: field}
}

func (m *RegMark) GetValue() uint32 {
	return m.value
}

func (m *RegMark) GetField() *RegField {
	return m.field
}

func (f *XXRegField) GetRegID() int {
	return f.regID
}

func (f *XXRegField) GetRange() *Range {
	return f.rng
}

func (f *XXRegField) GetNXFieldName() string {
	return fmt.Sprintf("%s%d", NxmFieldXXReg, f.regID)
}

func (f *XXRegField) isFullRange() bool {
	return f.rng.Length() == 128
}

func NewXXRegField(id int, start, end uint32) *XXRegField {
	return &XXRegField{regID: id, rng: &Range{start, end}}
}

func (m *CtMark) GetRange() *Range {
	return m.field.rng
}

// GetValue gets CT mark value with offset since CT mark is used by bit. E.g, CT_MARK_REG[3]==1, the return
// value of this function is 0b1000.
func (m *CtMark) GetValue() uint32 {
	return m.value << m.field.rng.Offset()
}

func (m *CtMark) isFullRange() bool {
	return m.field.rng.Length() == 32
}

func NewCTMarkField(start, end uint32) *CtMarkField {
	return &CtMarkField{rng: &Range{start, end}}
}

func NewOneBitCTMark(bit uint32) *CtMark {
	field := NewCTMarkField(bit, bit)
	return &CtMark{value: 1, field: field}
}

func NewOneBitZeroCTMark(bit uint32) *CtMark {
	field := NewCTMarkField(bit, bit)
	return &CtMark{value: 0, field: field}
}

func NewCTMark(field *CtMarkField, value uint32) *CtMark {
	return &CtMark{value: value, field: field}
}

func NewCTLabel(start, end uint32, name string) *CtLabel {
	return &CtLabel{name: name, rng: &Range{start, end}}
}

func (f *CtLabel) GetNXFieldName() string {
	return NxmFieldCtLabel
}

func (f *CtLabel) GetName() string {
	return f.name
}

func (f *CtLabel) GetRange() *Range {
	return f.rng
}
