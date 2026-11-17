package platform

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	conf := `# comment
search example.org
nameserver 192.0.2.1
nameserver 2001:db8::53
nameserver fe80::1%en0
nameserver not-an-ip
options ndots:2
`
	got, err := ParseResolvConf(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1:53", "[2001:db8::53]:53", "[fe80::1]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSystemResolversDoesNotFail(t *testing.T) {
	if _, err := SystemResolvers(); err != nil {
		t.Fatal(err)
	}
}
