package detect

import (
	"slices"
	"sync"
	"testing"
)

// Clone は、元の Detector と同じ結果を返し、別の goroutine から同時に使える(-race で確かめる)。
func TestCloneDetectsTheSameInParallel(t *testing.T) {
	d, err := New(Options{Deny: []string{"acme"}, Domains: []string{"example.co.jp"}, Allow: map[string]struct{}{"10.0.0.1": {}}})
	if err != nil {
		t.Fatal(err)
	}
	line := []byte("taro@acme.co.jp 10.0.0.1 10.0.0.2 db.example.co.jp password=abc <email_1>")
	want, wantKept := d.Find(line, nil)
	if len(want) == 0 || wantKept == 0 {
		t.Fatalf("got %+v, %d", want, wantKept)
	}
	var wg sync.WaitGroup
	for range 4 {
		c := d.Clone()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				got, kept := c.Find(line, nil)
				if !slices.Equal(got, want) || kept != wantKept {
					t.Errorf("got %+v, %d", got, kept)
					return
				}
			}
		}()
	}
	wg.Wait()
}
