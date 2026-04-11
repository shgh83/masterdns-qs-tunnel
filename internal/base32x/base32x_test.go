package base32x

import "testing"

func TestRoundTrip(t *testing.T) {
	encoded := EncodeLowerNoPadding([]byte("masterdns-qs-tunnel"))
	decoded, err := DecodeLowerNoPadding(encoded)
	if err != nil {
		t.Fatalf("DecodeLowerNoPadding returned error: %v", err)
	}
	if string(decoded) != "masterdns-qs-tunnel" {
		t.Fatalf("unexpected decoded payload: %q", decoded)
	}
}

func TestNumberRoundTrip(t *testing.T) {
	raw, err := NumberToLowerBase32(12345, 4)
	if err != nil {
		t.Fatalf("NumberToLowerBase32 returned error: %v", err)
	}
	value, err := Base32ToNumber(raw)
	if err != nil {
		t.Fatalf("Base32ToNumber returned error: %v", err)
	}
	if value != 12345 {
		t.Fatalf("unexpected value %d", value)
	}
}
