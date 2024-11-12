package filter

import (
	"context"
	"net"
	"net/netip"
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

func (p *DNSFilterProvider) hostToIPs(ctx context.Context, host *string) ([]string, bool) {
	if *host == "" {
		return nil, false
	}

	addrs, err := p.resolver.LookupHost(ctx, *host)
	if err != nil {
		return nil, false
	}
	return addrs, true
}

func (p *DNSFilterProvider) hostsToIPs(ctx context.Context) (mapset.Set[string], bool) {
	if *p.Raw == "" ||
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") {
		return nil, false
	}

	hosts := strings.Split(*p.Raw, ",")
	if len(hosts) == 0 || (len(hosts) == 1 && hosts[0] == "") {
		return nil, false
	}

	ipSet := mapset.NewThreadUnsafeSet[string]()
	for _, host := range hosts {
		if host == "" ||
			strings.EqualFold(host, "ALL") ||
			strings.EqualFold(host, "ANY") {
			continue
		}

		if IPs, ok := p.hostToIPs(ctx, &host); ok {
			for _, IP := range IPs {
				if addr, err := netip.ParseAddr(IP); err == nil {
					ipSet.Add(addr.String())
				}
			}
		}
	}

	return ipSet, true
}

func (p *DNSFilterProvider) Get(ctx context.Context) (*string, bool) {
	if ipSet, ok := p.hostsToIPs(ctx); ok && ipSet != nil && !ipSet.IsEmpty() {
		filter := stringFormatter.Format("host {0}", strings.Join(ipSet.ToSlice(), " or host "))
		return &filter, true
	}
	return nil, false
}

func (p *DNSFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("DNSFilter[{0}] => ({1})", *p.Raw, *filter)
	}
	return "DNSFilter[nil]"
}

func (p *DNSFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newDNSFilterProvider(filter *pcap.PcapFilter) pcap.PcapFilterProvider {
	return &DNSFilterProvider{
		PcapFilter: filter,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

func newDNSFilterProviderFromRawFilter(rawFilter *string) pcap.PcapFilterProvider {
	return newDNSFilterProvider(&pcap.PcapFilter{Raw: rawFilter})
}
