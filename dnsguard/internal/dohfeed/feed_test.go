package dohfeed

import "testing"

func TestParseLines(t *testing.T) {
	text := `
# comment
1.1.1.1
8.8.8.8 # trailing comment
dns.google
cloudflare-dns.com
2001:4860:4860::8888
not a domain!!
`
	domains, ips, err := parseLines(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 ips, got %d: %v", len(ips), ips)
	}
	found := map[string]bool{}
	for _, d := range domains {
		found[d] = true
	}
	if !found["dns.google"] || !found["cloudflare-dns.com"] {
		t.Fatalf("domains missing: %v", domains)
	}
}

func TestParseJSON(t *testing.T) {
	text := `[
	  {"name":"google","url":"https://dns.google/dns-query","ips":["8.8.8.8","8.8.4.4"]},
	  {"name":"cloudflare","url":"https://cloudflare-dns.com/dns-query","ips":["1.1.1.1"]}
	]`
	domains, ips, err := parseJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || len(ips) != 3 {
		t.Fatalf("got domains=%v ips=%v", domains, ips)
	}
}
