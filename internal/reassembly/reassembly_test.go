package reassembly

import (
	"testing"
	"time"
)

func TestAssemblerOutOfOrder(t *testing.T) {
	assembler := New(10 * time.Second)
	if _, complete, err := assembler.Add(1, 1, true, []byte("world")); err != nil || complete {
		t.Fatalf("unexpected first add state: complete=%v err=%v", complete, err)
	}
	out, complete, err := assembler.Add(1, 0, false, []byte("hello "))
	if err != nil {
		t.Fatalf("unexpected add error: %v", err)
	}
	if !complete {
		t.Fatalf("expected assembly to be complete")
	}
	if string(out) != "hello world" {
		t.Fatalf("unexpected assembled data %q", out)
	}
}
