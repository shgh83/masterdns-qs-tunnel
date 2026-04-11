package base36x

import (
	"bytes"
	"testing"
)

func TestLowerBase36RoundTrip(t *testing.T) {
	original := []byte("masterdns-qs-tunnel-uplink")
	encoded := EncodeLowerBase36Bytes(original)
	decoded, err := DecodeLowerBase36(encoded)
	if err != nil {
		t.Fatalf("DecodeLowerBase36 returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("round-trip mismatch")
	}
}
