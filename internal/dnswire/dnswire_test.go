package dnswire

import "testing"

func TestBuildAndParseQuery(t *testing.T) {
	qname, err := EncodeDomain("t.example.com")
	if err != nil {
		t.Fatalf("EncodeDomain returned error: %v", err)
	}
	packet := BuildQuery(qname, 42, 1)
	query, err := ParseQuery(packet)
	if err != nil {
		t.Fatalf("ParseQuery returned error: %v", err)
	}
	if query.ID != 42 {
		t.Fatalf("unexpected query id %d", query.ID)
	}
	if query.QType != 1 {
		t.Fatalf("unexpected qtype %d", query.QType)
	}
	if len(query.Labels) != 3 {
		t.Fatalf("unexpected labels len %d", len(query.Labels))
	}
}
