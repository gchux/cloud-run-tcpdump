package filter

import (
	"context"
	"fmt"
	"os"

	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	pcapFilterProviderFactory = func(*pcap.PcapFilter) pcap.PcapFilterProvider
)

func applyFilter(
	ctx context.Context,
	srcFilter *string,
	provider pcap.PcapFilterProvider,
	mode pcap.PcapFilterMode,
) *string {
	filter, ok := provider.Get(ctx)
	if !ok || *filter == "" {
		return srcFilter
	}

	switch mode {
	case pcap.PCAP_FILTER_MODE_AND:
		*filter = stringFormatter.Format("{0} and ({1})", *srcFilter, *filter)
	case pcap.PCAP_FILTER_MODE_OR:
		*filter = stringFormatter.Format("{0} or ({1})", *srcFilter, *filter)
	}
	return filter
}

func newPcapFilter(rawFilter *string) *pcap.PcapFilter {
	return &pcap.PcapFilter{
		Raw: rawFilter,
	}
}

func newPcapFilterProvider(
	rawFilter *string,
	factory pcapFilterProviderFactory,
) pcap.PcapFilterProvider {
	pcapFilter := newPcapFilter(rawFilter)
	return factory(pcapFilter)
}

func NewDNSFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	fmt.Fprintln(os.Stderr, "=>", *rawFilter)
	return newPcapFilterProvider(rawFilter, newDNSFilterProvider)
}

func NewTCPFlagsFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	fmt.Fprintln(os.Stderr, "=>", *rawFilter)
	return newPcapFilterProvider(rawFilter, newTCPFlagsFilterProvider)
}
