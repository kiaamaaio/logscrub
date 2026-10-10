package label

import "testing"

func TestTypeIndex(t *testing.T) {
	for i, typ := range Types {
		if got := TypeIndex(typ); got != i {
			t.Errorf("TypeIndex(%q) = %d, want %d", typ, got, i)
		}
	}
	for _, typ := range []string{"", "ipv4", "ipv6", "Email", "email ", "phone"} {
		if got := TypeIndex(typ); got != -1 {
			t.Errorf("TypeIndex(%q) = %d, want -1", typ, got)
		}
	}
}
