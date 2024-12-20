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

	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	pcapFilterProviderFactory = func(*pcap.PcapFilter) pcap.PcapFilterProvider
	PcapFilterProviderFactory = func(*string) pcap.PcapFilterProvider
)

func applyFilter(
	ctx context.Context,
	srcFilter *string,
	provider pcap.PcapFilterProvider,
	mode pcap.PcapFilterMode,
) *string {
	if provider == nil {
		return srcFilter
	}

	filter, ok := provider.Get(ctx)
	if !ok || filter == nil || *filter == "" {
		return srcFilter
	}

	if srcFilter == nil || *srcFilter == "" {
		*filter = stringFormatter.Format("({0})", *filter)
		return filter
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

func NewIPFilterProvider(ipv4RawFilter, ipv6RawFilter, dnsRawFilter *string) pcap.PcapFilterProvider {
	return newIPFilterProvider(ipv4RawFilter, ipv6RawFilter, dnsRawFilter)
}

func NewDNSFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, newDNSFilterProvider)
}

func NewL3ProtoFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, newL3ProtoFilterProvider)
}

func NewL4ProtoFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, newL4ProtoFilterProvider)
}

func NewPortsFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, newPortsFilterProvider)
}

func NewTCPFlagsFilterProvider(rawFilter *string) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, newTCPFlagsFilterProvider)
}
