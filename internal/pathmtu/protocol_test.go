package pathmtu

import "testing"

func TestProbeCorrelationRejectsChangedSizeNonceAndShape(t *testing.T) {
	request, err := Request(1500)
	if err != nil {
		t.Fatal(err)
	}
	reply := Reply(request)
	if !Matches(request, reply) {
		t.Fatal("valid response rejected")
	}
	for _, at := range []int{0, 4, 5, 6, 8, 23} {
		bad := append([]byte(nil), reply...)
		bad[at] ^= 1
		if Matches(request, bad) {
			t.Fatal("changed response accepted", at)
		}
	}
	if Matches(request, append(reply, 0)) || Matches(request[:8], reply) {
		t.Fatal("bad shape accepted")
	}
	if _, err := Request(1501); err == nil {
		t.Fatal("unbounded request")
	}
}
