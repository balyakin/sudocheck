package scanner

import "testing"

func TestParseCapabilities(t *testing.T) {
	output := `/usr/bin/python3.11 cap_setuid+ep
/usr/bin/ping cap_net_raw=ep`

	files := ParseCapabilities(output)

	if len(files) != 2 {
		t.Fatalf("expected 2 capability files, got %d", len(files))
	}
	if files[0].BinaryName != "python3.11" {
		t.Fatalf("unexpected binary name: %s", files[0].BinaryName)
	}
	if files[0].Capabilities[0] != "cap_setuid+ep" {
		t.Fatalf("unexpected capability: %s", files[0].Capabilities[0])
	}
}
