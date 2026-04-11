package protocol

import (
	"bytes"
	"testing"
	"time"

	"github.com/blackestwhite/masterdns-qs-tunnel/internal/dnswire"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/reassembly"
)

func TestChunkRoundTrip(t *testing.T) {
	plans, err := PrepareDomainPlans([]string{"t.example.com"}, 253, 63, 3, 7)
	if err != nil {
		t.Fatalf("PrepareDomainPlans returned error: %v", err)
	}
	matchers, err := PrepareMatchers([]string{"t.example.com"})
	if err != nil {
		t.Fatalf("PrepareMatchers returned error: %v", err)
	}

	frame := BuildDataFrame(bytes.Repeat([]byte("abc123"), 30))
	qnames, _, err := BuildQNames(frame, 7, "abc1234", plans, 0, 63, 3)
	if err != nil {
		t.Fatalf("BuildQNames returned error: %v", err)
	}

	assembler := reassembly.New(10 * time.Second)
	for _, qname := range qnames {
		packet := dnswire.BuildQuery(qname, 1, 1)
		query, err := dnswire.ParseQuery(packet)
		if err != nil {
			t.Fatalf("ParseQuery returned error: %v", err)
		}
		matcher, suffixLen, ok := MatchDomain(query.Labels, matchers)
		if !ok {
			t.Fatalf("MatchDomain failed")
		}
		chunk, err := ParseChunk(query.Labels, matcher, suffixLen, 7, 3)
		if err != nil {
			t.Fatalf("ParseChunk returned error: %v", err)
		}
		encoded, complete, err := assembler.Add(chunk.Offset, chunk.FragmentIndex, chunk.Last, chunk.EncodedData)
		if err != nil {
			t.Fatalf("Assembler returned error: %v", err)
		}
		if complete {
			if !bytes.Equal(encoded, frame) {
				t.Fatalf("round-trip mismatch")
			}
			return
		}
	}

	t.Fatalf("did not complete assembly")
}
