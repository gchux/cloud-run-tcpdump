package filter

import (
	"context"
	"net/netip"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	IPFilterProvider struct {
		ipv4Filter        *pcap.PcapFilter
		ipv6Filter        *pcap.PcapFilter
		dnsFilterProvider *DNSFilterProvider
	}
)

const DEFAULT_IP_FILTER = "net 0.0.0.0/0 or net ::/0"

func (p *IPFilterProvider) getIPsAndNETs(_ context.Context) ([]string, []string) {
	if *p.ipv4Filter.Raw == "" && *p.ipv6Filter.Raw == "" {
		return []string{}, []string{}
	}

	rawIPs := stringFormatter.Format("{0},{1}",
		*p.ipv4Filter.Raw, *p.ipv6Filter.Raw)
	allIPsOrNETs := strings.Split(rawIPs, ",")

	IPs := []string{}
	NETs := []string{}

	for _, IPorNET := range allIPsOrNETs {
		if IPorNET == "" || strings.EqualFold(IPorNET, "DISABLED") {
			continue
		} else if strings.EqualFold(IPorNET, "ALL") || strings.EqualFold(IPorNET, "ANY") {
			NETs = append(NETs, "0.0.0.0/0")
			NETs = append(NETs, "::/0")
		} else if addr, err := netip.ParseAddr(IPorNET); err == nil {
			if addr.Is4() || addr.Is6() {
				IPs = append(IPs, addr.String())
			}
		} else if net, err := netip.ParsePrefix(IPorNET); err == nil {
			if net.IsValid() {
				NETs = append(NETs, net.String())
			}
		}
	}

	return IPs, NETs
}

func (p *IPFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.ipv4Filter.Raw == "" &&
		*p.ipv6Filter.Raw == "" &&
		*p.dnsFilterProvider.Raw == "" {
		return nil, false
	}

	IPs, NETs := p.getIPsAndNETs(ctx)
	ipSet := mapset.NewThreadUnsafeSet(IPs...)
	if IPs, ok := p.dnsFilterProvider.hostsToIPs(ctx); ok && !IPs.IsEmpty() {
		ipSet.Append(IPs.ToSlice()...)
	}

	for _, net := range NETs {
		NET, _ := netip.ParsePrefix(net)
		// this is potentially very slow/expensive: O(IP^NET)
		// we prefer to pay the price only once here,
		// instead of having a complex/slow BPF filter.
		ipSet.Each(func(ip string) bool {
			IP, _ := netip.ParseAddr(ip)
			if NET.Contains(IP) {
				// if any NET already contains this IP,
				// then keep the NET and drop the IP.
				ipSet.Remove(ip)
			}
			return false
		})
	}
	netSet := mapset.NewThreadUnsafeSet(NETs...)

	ipFilter := ""
	if !ipSet.IsEmpty() {
		ipFilter = stringFormatter.Format("host {0}",
			strings.Join(ipSet.ToSlice(), " or host "))
	}

	netFilter := ""
	if !netSet.IsEmpty() {
		netFilter = stringFormatter.Format("net {0}",
			strings.Join(netSet.ToSlice(), " or net "))
	}

	filter := ""
	if ipFilter != "" && netFilter != "" {
		filter = stringFormatter.Format("({0}) or ({1})", ipFilter, netFilter)
	} else if ipFilter != "" {
		filter = ipFilter
	} else if netFilter != "" {
		filter = netFilter
	} else {
		filter = string(DEFAULT_IP_FILTER)
	}

	return &filter, true
}

func (p *IPFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("IPFilter[{0}|{1}|{2}] => ({3})",
			*p.ipv4Filter.Raw, *p.ipv6Filter.Raw, *p.dnsFilterProvider.Raw, *filter)
	}
	return "IPFilter[nil]"
}

func (p *IPFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newIPFilterProvider(
	ipv4RawFilter, ipv6RawFilter, dnsRawFiler *string,
) pcap.PcapFilterProvider {
	provider := &IPFilterProvider{
		ipv4Filter:        &pcap.PcapFilter{Raw: ipv4RawFilter},
		ipv6Filter:        &pcap.PcapFilter{Raw: ipv6RawFilter},
		dnsFilterProvider: newDNSFilterProviderFromRawFilter(dnsRawFiler).(*DNSFilterProvider),
	}
	return provider
}
