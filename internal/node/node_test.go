package node

import "testing"

func TestState(t *testing.T) {
	s := inactive
	s = s | trusted
	if s != trusted {
		t.Fatalf("S is %b", s)
	}

	s = s & inactive

	if s != inactive {
		t.Fatalf("S is %b", s)
	}
}
