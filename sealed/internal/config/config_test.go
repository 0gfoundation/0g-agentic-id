package config

import "testing"

// VERIFIED_FEEDBACK_ADDR is normalized at boot: anything that can't name the
// registry proxy becomes "" (serve-proofs off), never a partial value the
// proxy might sign against.
func TestVerifiedFeedbackAddr_Normalizes(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"unset", "", ""},
		{"blank", "   ", ""},
		{"malformed", "0x1234", ""},
		{"not hex", "0xZZ000000000000000000000000000000000000B7", ""},
		{"zero address", "0x0000000000000000000000000000000000000000", ""},
		// EIP-55's own test vector.
		{"lowercase → checksummed", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"surrounding space", " 0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED\n", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
	}
	for _, c := range cases {
		if got := verifiedFeedbackAddr(c.raw); got != c.want {
			t.Errorf("%s: verifiedFeedbackAddr(%q) = %q, want %q", c.name, c.raw, got, c.want)
		}
	}
}
