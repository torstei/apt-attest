package text

import "testing"

func TestSafe(t *testing.T) {
	bs := string(rune(0x5c))
	cases := map[string]string{
		"pidvault_0.6.0-1_amd64.deb":            "pidvault_0.6.0-1_amd64.deb",
		"https://github.com/torstei/pidvault":   "https://github.com/torstei/pidvault",
		"a\x1b[2K\rapt-attest: ok":              "a" + bs + "x1b[2K" + bs + "rapt-attest: ok",
		"x\napt-attest: pidvault attested by y": "x" + bs + "napt-attest: pidvault attested by y",
		"\x1b]52;c;ZWNobyBoaQ==\x07":            bs + "x1b]52;c;ZWNobyBoaQ==" + bs + "a",
		"evil" + string(rune(0x202e)) + "gnp":   "evil" + bs + "u202egnp",
		string(rune(0x9b)) + "31m":              bs + "u009b31m",
		"bad \xff byte":                         "bad " + bs + "ufffd byte",
	}
	for in, want := range cases {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}
