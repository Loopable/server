package events

import "testing"

func TestEventTypeRegistry(t *testing.T) {
	definition, err := LookupType(0)
	if err != nil || definition.Authorization != Genesis {
		t.Fatalf("genesis definition = %+v, error = %v", definition, err)
	}
	definition, err = LookupType(13)
	if err != nil || definition.Authorization != Authorized {
		t.Fatalf("post definition = %+v, error = %v", definition, err)
	}
	for _, code := range []uint64{10, 11, 26} {
		if _, err := LookupType(code); err == nil {
			t.Errorf("accepted invalid event type %d", code)
		}
	}
}
