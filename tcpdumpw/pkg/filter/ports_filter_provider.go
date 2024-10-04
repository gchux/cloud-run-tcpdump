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
	PortsFilterProvider struct {
		*pcap.PcapFilter
	}
)

func (p *PortsFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" {
		return nil, false
	}

	ports := strings.Split(strings.ToLower(*p.Raw), ",")
	if len(ports) == 0 || (len(ports) == 1 && ports[0] == "") {
		return nil, false
	}

	portSet := mapset.NewThreadUnsafeSet(ports...)
	portSet.Each(func(portStr string) bool {
		if portStr == "" || strings.EqualFold(portStr, "ALL") || strings.EqualFold(portStr, "ANY") {
			portSet.Remove(portStr)
		} else if port, err := strconv.ParseUint(portStr, 10, 16); err != nil || port > 0xFFFF {
			// a PORT must be a number not greater than 65535
			portSet.Remove(portStr)
		}
		return false
	})

	if portSet.IsEmpty() {
		return nil, false
	}

	filter := stringFormatter.Format("port {0}",
		strings.Join(portSet.ToSlice(), " or port "))

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
