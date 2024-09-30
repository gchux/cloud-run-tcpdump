package filter

import (
	"context"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	PortsFilterProvider struct {
		*pcap.PcapFilter
	}
)

func (p *PortsFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" {
		return nil, false
	}

	flags := strings.Split(strings.ToLower(*p.Raw), ",")
	if len(flags) == 0 || (len(flags) == 1 && flags[0] == "") {
		return nil, false
	}

	flagsSet := mapset.NewThreadUnsafeSet(flags...)
	filter := stringFormatter.Format("port {0}",
		strings.Join(flagsSet.ToSlice(), " or port "))

	return &filter, true
}

func (p *PortsFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("PortsFilter[{0}] => ({1})", *p.Raw, *filter)
	}
	return "PortsFilter[nil]"
}

func (p *PortsFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newPortsFilterProvider(filter *pcap.PcapFilter) pcap.PcapFilterProvider {
	provider := &PortsFilterProvider{
		PcapFilter: filter,
	}
	return provider
}
