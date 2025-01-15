// Copyright 2024 Google LLC
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

package filter

import (
	"context"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	TCPFlagsFilterProvider struct {
		*pcap.PcapFilter
		pcap.PcapFilters
	}
)

var (
	tcpSynStr = "syn"
	tcpAckStr = "ack"
	tcpPshStr = "psh"
	tcpFinStr = "fin"
	tcpRstStr = "rst"
	tcpUrgStr = "urg"
	tcpEceStr = "ece"
	tcpCwrStr = "cwr"

	tcpFlags = map[string]uint8{
		tcpFinStr: 0b00000001,
		tcpSynStr: 0b00000010,
		tcpRstStr: 0b00000100,
		tcpPshStr: 0b00001000,
		tcpAckStr: 0b00010000,
		tcpUrgStr: 0b00100000,
		tcpEceStr: 0b01000000,
		tcpCwrStr: 0b10000000,
	}
)

func (p *TCPFlagsFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" ||
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") {
		return nil, false
	}

	flags := strings.Split(strings.ToLower(*p.Raw), ",")
	if len(flags) == 0 || (len(flags) == 1 && flags[0] == "") {
		return nil, false
	}

	flagsSet := mapset.NewThreadUnsafeSet(flags...)

	var setFlags uint8 = 0
	flagsSet.Each(func(flagStr string) bool {
		if flag, ok := tcpFlags[flagStr]; ok {
			setFlags |= flag
			_flagStr := strings.ToUpper(flagStr)
			p.AddTCPFlags(pcap.TCPFlag(_flagStr))
		} else {
			flagsSet.Remove(flagStr)
		}
		return false // do not stop iteration
	})

	if setFlags == 0 || flagsSet.IsEmpty() {
		return nil, false
	}

	ip6Filter := stringFormatter.Format("ip6[13+40]&0x{0}!=0", strconv.FormatUint(uint64(setFlags), 16))
	// OR'ing out all the TCP flags: if any of the flags is set, packet will be captured
	ip4Filter := stringFormatter.Format("tcp-{0}", strings.Join(flagsSet.ToSlice(), "|tcp-"))
	// bitwise intersection should not yield 0, so intersection must not be empty
	filter := stringFormatter.Format("(tcp[tcpflags]&({0})!=0) or ({1})", ip4Filter, ip6Filter)

	return &filter, true
}

func (p *TCPFlagsFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("TCPFlagsFilter[{0}] => ({1})", *p.Raw, *filter)
	}
	return "TCPFlagsFilter[nil]"
}

func (p *TCPFlagsFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newTCPFlagsFilterProvider(
	filter *pcap.PcapFilter,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	provider := &TCPFlagsFilterProvider{
		PcapFilter:  filter,
		PcapFilters: compatFilters,
	}
	return provider
}
