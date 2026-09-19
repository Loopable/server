package capabilities

import "testing"

func TestNegotiateMandatoryAndOptionalCapabilities(t *testing.T) {
	local := []Capability{{ID: "events", Version: "0.1", Mandatory: true}, {ID: "webpush", Version: "0.1"}}
	remote := []Capability{{ID: "events", Version: "0.1", Mandatory: true}, {ID: "unknown", Version: "9.1"}}
	negotiated, err := Negotiate(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(negotiated) != 1 || negotiated[0].ID != "events" {
		t.Fatalf("negotiated = %+v", negotiated)
	}
}

func TestRejectsMandatoryMismatch(t *testing.T) {
	if _, err := Negotiate([]Capability{{ID: "events", Version: "0.1", Mandatory: true}}, nil); err == nil {
		t.Fatal("accepted missing mandatory capability")
	}
	if _, err := Negotiate(nil, []Capability{{ID: "events", Version: "0.1", Mandatory: true}}); err == nil {
		t.Fatal("accepted peer mandatory capability")
	}
}
