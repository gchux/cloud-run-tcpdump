package filter

import (
	"context"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	TCPFlagsFilterProvider struct {
		*pcap.PcapFilter
	}
)

func (p *TCPFlagsFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" {
		return nil, false
	}

	flags := strings.Split(strings.ToLower(*p.Raw), ",")
	if len(flags) == 0 || (len(flags) == 1 && flags[0] == "") {
		return nil, false
	}

	flagsSet := mapset.NewThreadUnsafeSet(flags...)
	// OR'ing out all the TCP flags: if any of the flags is set, packet will be captured
	filter := stringFormatter.Format("tcp-{0}", strings.Join(flagsSet.ToSlice(), "|tcp-"))
	// bitwise intersection should not yield 0, so intersection must not be empty
	filter = stringFormatter.Format("tcp[tcpflags] & ({0}) != 0", filter)

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

func newTCPFlagsFilterProvider(filter *pcap.PcapFilter) pcap.PcapFilterProvider {
	provider := &TCPFlagsFilterProvider{
		PcapFilter: filter,
	}
	return provider
}
