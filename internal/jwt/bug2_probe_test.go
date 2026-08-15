package jwt

import (
	"encoding/json"
	"testing"
)

// Regression probe: non-string standard claims (e.g. aud as array, jti as number)
// should be preserved in Extra rather than silently dropped.
func TestProbe_NonStringStandardClaimPreservedInExtra(t *testing.T) {
	data := []byte(`{"sub":"alice","aud":["svc-1","svc-2"],"jti":12345}`)
	var c Claims
	err := json.Unmarshal(data, &c)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Extra["aud"] == nil {
		t.Fatalf("aud array was silently dropped; expected it in Extra")
	}
	audSlice, ok := c.Extra["aud"].([]any)
	if !ok {
		t.Fatalf("Extra[aud] should be []any, got %T", c.Extra["aud"])
	}
	if len(audSlice) != 2 || audSlice[0] != "svc-1" || audSlice[1] != "svc-2" {
		t.Fatalf("aud content mismatch: %v", audSlice)
	}
	if c.Extra["jti"] == nil {
		t.Fatalf("numeric jti was silently dropped; expected it in Extra")
	}
}
