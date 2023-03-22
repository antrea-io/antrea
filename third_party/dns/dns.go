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

// This package is copied and modified from https://github.com/miekg/dns because the original function Unpack cannot
// unpack fragmented DNS message.

package dns

import (
	"encoding/binary"
	"fmt"

	godns "github.com/miekg/dns"
)

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authenticated data
	_CD = 1 << 4  // checking disabled
)

// UnpackDNSMsgPartially is modified from https://github.com/miekg/dns/blob/6ad6301ae27dca6d7822baf1b05ff9c9e4ba56f4/msg.go#L883.
// It can unpack a DNS response with partial data only. More specifically, it unpacks the message header, the question
// section, and the answer section, while ignores the authority section and the additional section.
// It's used to get the question and answer sections when a DNS response is carried by a TCP packet but is fragmented.
func UnpackDNSMsgPartially(msg []byte, dns *godns.Msg) error {
	dh, off, err := unpackMsgHdr(msg, 0)
	if err != nil {
		return err
	}

	setHdr(dns, dh)
	return unpackPartially(dns, dh, msg, off)
}

func unpackMsgHdr(msg []byte, off int) (godns.Header, int, error) {
	var (
		dh  godns.Header
		err error
	)
	dh.Id, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Bits, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Qdcount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Ancount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Nscount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Arcount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	return dh, off, nil
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), fmt.Errorf("overflow unpacking uint16")
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func setHdr(dns *godns.Msg, dh godns.Header) {
	dns.Id = dh.Id
	dns.Response = dh.Bits&_QR != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = dh.Bits&_AA != 0
	dns.Truncated = dh.Bits&_TC != 0
	dns.RecursionDesired = dh.Bits&_RD != 0
	dns.RecursionAvailable = dh.Bits&_RA != 0
	dns.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	dns.AuthenticatedData = dh.Bits&_AD != 0
	dns.CheckingDisabled = dh.Bits&_CD != 0
	dns.Rcode = int(dh.Bits & 0xF)
}

// unpackPartially is modified from https://github.com/miekg/dns/blob/6ad6301ae27dca6d7822baf1b05ff9c9e4ba56f4/msg.go#L826.
// It unpacks the message header, the question section, and the answer section, while ignores the authority section and
// the additional section.
func unpackPartially(dns *godns.Msg, dh godns.Header, msg []byte, off int) (err error) {
	// If we are at the end of the message we should return *just* the
	// header. This can still be useful to the caller. 9.9.9.9 sends these
	// when responding with REFUSED for instance.
	if off == len(msg) {
		// reset sections before returning
		dns.Question, dns.Answer, dns.Ns, dns.Extra = nil, nil, nil, nil
		return nil
	}

	// Qdcount, Ancount, Nscount, Arcount can't be trusted, as they are
	// attacker controlled. This means we can't use them to pre-allocate
	// slices.
	dns.Question = nil
	for i := 0; i < int(dh.Qdcount); i++ {
		off1 := off
		var q godns.Question
		q, off, err = unpackQuestion(msg, off)
		if err != nil {
			return err
		}
		if off1 == off { // Offset does not increase anymore, dh.Qdcount is a lie!
			dh.Qdcount = uint16(i)
			break
		}
		dns.Question = append(dns.Question, q)
	}

	dns.Answer, off, err = unpackRRslice(int(dh.Ancount), msg, off)
	// The header counts might have been wrong so we need to update it
	dh.Ancount = uint16(len(dns.Answer))
	// Skip unpacking the authority section and the additional section.
	return err

}

func unpackQuestion(msg []byte, off int) (godns.Question, int, error) {
	var (
		q   godns.Question
		err error
	)
	q.Name, off, err = godns.UnpackDomainName(msg, off)
	if err != nil {
		return q, off, err
	}
	if off == len(msg) {
		return q, off, nil
	}
	q.Qtype, off, err = unpackUint16(msg, off)
	if err != nil {
		return q, off, err
	}
	if off == len(msg) {
		return q, off, nil
	}
	q.Qclass, off, err = unpackUint16(msg, off)
	if off == len(msg) {
		return q, off, nil
	}
	return q, off, err
}

// unpackRRslice unpacks msg[off:] into an []RR.
// If we cannot unpack the whole array, then it will return nil
func unpackRRslice(l int, msg []byte, off int) (dst1 []godns.RR, off1 int, err error) {
	var r godns.RR
	// Don't pre-allocate, l may be under attacker control
	var dst []godns.RR
	for i := 0; i < l; i++ {
		off1 := off
		r, off, err = godns.UnpackRR(msg, off)
		if err != nil {
			off = len(msg)
			break
		}
		// If offset does not increase anymore, l is a lie
		if off1 == off {
			break
		}
		dst = append(dst, r)
	}
	if err != nil && off == len(msg) {
		dst = nil
	}
	return dst, off, err
}
