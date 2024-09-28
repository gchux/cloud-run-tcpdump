package filter

import (
	"context"
	"net"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	DNSFilterProvider struct {
		*pcap.PcapFilter
		resolver *net.Resolver
	}
)

func (p *DNSFilterProvider) hostToIPs(ctx context.Context, host *string) []string {
	if *host == "" {
		return []string{}
	}

	addrs, err := p.resolver.LookupHost(ctx, *host)
	if err != nil {
		return []string{}
	}

	return addrs
}

func (p *DNSFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" {
		return nil, false
	}

	hosts := strings.Split(*p.Raw, ",")
	if len(hosts) == 0 || (len(hosts) == 1 && hosts[0] == "") {
		return nil, false
	}

	ipSet := mapset.NewThreadUnsafeSet[string]()
	for _, host := range hosts {
		IPs := p.hostToIPs(ctx, &host)
		ipSet.Append(IPs...)
	}

	filter := stringFormatter.Format("host {0}",
		strings.Join(ipSet.ToSlice(), " or host "))
	return &filter, true
}

func (p *DNSFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return *filter
	}
	return ""
}

func (p *DNSFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newDNSFilterProvider(filter *pcap.PcapFilter) pcap.PcapFilterProvider {
	provider := &DNSFilterProvider{
		PcapFilter: filter,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
	return provider
}
