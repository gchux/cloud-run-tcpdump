package filter

import (
	"context"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	L3ProtoFilterProvider struct {
		*pcap.PcapFilter
	}
)

const (
	l3_PROTO_DEFAULT_FILTER string = "ip or ip6"
	l3_PROTO_IPv4_FILTER    string = "ip"
	l3_PROTO_IPv6_FILTER    string = "ip6"
)

func (p *L3ProtoFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" ||
		*p.Raw == "45" || // IPv4(4) + IPv6(41)
		*p.Raw == "0x2D" || // IPv4(0x04) + IPv6(0x29)
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") ||
		strings.EqualFold(*p.Raw, l3_PROTO_DEFAULT_FILTER) {
		filter := string(l3_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	protos := strings.Split(*p.Raw, ",")
	if len(protos) == 0 || (len(protos) == 1 && protos[0] == "") {
		filter := string(l3_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	l3Protos := mapset.NewThreadUnsafeSet[string]()

	for _, proto := range protos {
		switch proto {
		case "ip", "ip4", "ipv4", "4", "0x04":
			l3Protos.Add(string(l3_PROTO_IPv4_FILTER))
		case "ip6", "ipv6", "41", "0x29":
			l3Protos.Add(string(l3_PROTO_IPv6_FILTER))
		}
	}

	if l3Protos.IsEmpty() {
		return nil, false
	}

	filter := stringFormatter.Format("{0}", strings.Join(l3Protos.ToSlice(), " or "))
	return &filter, true
}

func (p *L3ProtoFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("L3Proto[{0}] => ({1})", *p.Raw, *filter)
	}
	return "L3Proto[nil]"
}

func (p *L3ProtoFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newL3ProtoFilterProvider(filter *pcap.PcapFilter) pcap.PcapFilterProvider {
	provider := &L3ProtoFilterProvider{
		PcapFilter: filter,
	}
	return provider
}
