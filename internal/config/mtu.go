package config

// SafePayload is a conservative, local-link ceiling. It is not end-to-end
// PLPMTUD: a smaller MTU elsewhere on the path still needs an authenticated
// packet-size probe or an operator's smaller payload setting.
func SafePayload(profile, wire string, outerMTU, requested int) int {
	if profile == "tcp" || outerMTU <= 0 {
		return requested
	}
	frame := 60
	if wire == "opaque" {
		frame = 37
	}
	overhead := 20 + frame
	switch profile {
	case "bip":
		overhead = 152 // includes the largest legacy single-frame envelope
	case "udp":
		overhead += 8
	case "icmp":
		overhead += 8
		if wire != "opaque" {
			overhead += 4
		}
	case "gre", "ipip":
		overhead += 20
		if profile == "gre" {
			overhead += 4
		}
		if wire != "opaque" {
			overhead += 4
		}
	}
	return min(requested, outerMTU-overhead)
}
