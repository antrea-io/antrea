// Copyright 2023 Antrea Authors
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

package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godns "github.com/miekg/dns"
)

func TestUnpackDNSMsgPartially(t *testing.T) {
	name := "some-very-long-ownername.com."
	originalMsg := &godns.Msg{
		Compress: true,
		Answer: []godns.RR{
			&godns.NS{
				Hdr: godns.RR_Header{
					Name:     name,
					Rrtype:   godns.TypeNS,
					Class:    godns.ClassINET,
					Rdlength: 13,
				},
				Ns: "ns1.server.com.",
			},
			&godns.NSEC{
				Hdr: godns.RR_Header{
					Name:     name,
					Rrtype:   godns.TypeNSEC,
					Class:    godns.ClassINET,
					Rdlength: 15,
				},
				NextDomain: "a.com.",
				TypeBitMap: []uint16{godns.TypeNS, godns.TypeNSEC},
			},
		},
		Ns: []godns.RR{
			&godns.CNAME{
				Hdr: godns.RR_Header{
					Name:   "foo.example.com.",
					Rrtype: godns.TypeCNAME,
					Class:  godns.ClassINET,
					Ttl:    300,
				},
				Target: "bar.example.com.",
			},
		},
	}

	// Pack msg and then unpack into partialMsg
	originalBuf, err := originalMsg.Pack()
	require.NoError(t, err)
	// Without the last 10 bytes, it should be unpacked successfully.
	partialBuf := originalBuf[:len(originalBuf)-10]
	partialMsg := new(godns.Msg)
	err = UnpackDNSMsgPartially(partialBuf, partialMsg)
	require.NoError(t, err)
	assert.Equal(t, originalMsg.MsgHdr, partialMsg.MsgHdr)
	assert.Equal(t, originalMsg.Question, partialMsg.Question)
	assert.Equal(t, originalMsg.Answer, partialMsg.Answer)

	// With the beginning 10 bytes, it should not be unpacked successfully.
	partialBuf = originalBuf[:10]
	partialMsg = new(godns.Msg)
	err = UnpackDNSMsgPartially(partialBuf, partialMsg)
	require.Error(t, err)
}
