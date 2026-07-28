package util

import (
	"testing"
	"time"
)

// "300" is 300 seconds — an operator writes bare seconds as naturally as "5m",
// and rejecting it looped "invalid time unit" once a minute forever.
func TestConvertIntervalToDuration_BareSeconds(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"300": 300 * time.Second,
		"5m":  5 * time.Minute,
		"60":  time.Minute,
	} {
		s := in
		got, err := ConvertIntervalToDuration(&s)
		if err != nil || got != want {
			t.Fatalf("ConvertIntervalToDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	neg := "-5"
	if _, err := ConvertIntervalToDuration(&neg); err == nil {
		t.Fatal("a negative interval must be refused")
	}
}
