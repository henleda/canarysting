package observe

// fromRaw converts the bpf2go-generated map value (observeCsFlowStats, whose layout
// matches observe.bpf.c's struct flow_stats) into the clean userspace FlowStats
// the aggregator consumes, field for field. It is all-platform (the generated
// struct is a plain Go type) so layout_test can verify the parity on any host.
// layout_test.go pins both the generated struct's byte layout and this mapping.
func fromRaw(r observeCsFlowStats) FlowStats {
	return FlowStats{
		IngressPackets: r.IngressPackets,
		IngressBytes:   r.IngressBytes,
		EgressPackets:  r.EgressPackets,
		EgressBytes:    r.EgressBytes,
		FirstSeenNs:    r.FirstSeenNs,
		LastSeenNs:     r.LastSeenNs,
		Family:         r.Family,
		SrcPort:        r.SrcPort,
		DstPort:        r.DstPort,
		SrcIP:          r.SrcIp,
		DstIP:          r.DstIp,
	}
}
