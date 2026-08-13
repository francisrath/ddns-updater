//go:build integration

package rfc2136

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests below run against a BIND server accepting dynamic updates,
// which is defined in the testdata directory and started with:
//
//	docker build -t ddns-updater-bind ./testdata
//	docker run -d --name ddns-updater-bind -p 5354:53/tcp -p 5354:53/udp ddns-updater-bind
//
// It serves the zone example.com only accepting updates signed with the
// TSIG key below, and the zone open.com accepting unsigned updates.
// The tests are then run with:
//
//	go test -tags integration ./internal/provider/providers/rfc2136/
//
// Set the RFC2136_SERVER environment variable to use another address.
// Note the tests modify records, so the container should be recreated
// to run them against a pristine zone.
const (
	defaultTestServer = "127.0.0.1:5354"
	testTSIGKeyName   = "ddns-key"
	testTSIGSecret    = "dGVzdC1zZWNyZXQtZm9yLWRkbnMtdXBkYXRlcnM=" //nolint:gosec
	signedZone        = "example.com"
	testOwner         = "home"
)

func testServer() string {
	server := os.Getenv("RFC2136_SERVER")
	if server == "" {
		return defaultTestServer
	}
	return server
}

func Test_integration_Update(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		domain   string
		owner    string
		settings string
		ip       netip.Addr
	}{
		"update existing A record with TSIG": {
			domain: signedZone,
			owner:  testOwner,
			settings: fmt.Sprintf(`{"server":%q,"tsig_key_name":%q,"tsig_secret":%q}`,
				testServer(), testTSIGKeyName, testTSIGSecret),
			ip: netip.MustParseAddr("5.6.7.8"),
		},
		"create missing A record with TSIG": {
			domain: signedZone,
			owner:  "created",
			settings: fmt.Sprintf(`{"server":%q,"tsig_key_name":%q,"tsig_secret":%q,"ttl":60}`,
				testServer(), testTSIGKeyName, testTSIGSecret),
			ip: netip.MustParseAddr("9.9.9.9"),
		},
		"update AAAA record with TSIG": {
			domain: signedZone,
			owner:  "ipv6",
			settings: fmt.Sprintf(`{"server":%q,"tsig_key_name":%q,"tsig_secret":%q}`,
				testServer(), testTSIGKeyName, testTSIGSecret),
			ip: netip.MustParseAddr("2001:db8::abcd"),
		},
		"update root of the zone with TSIG": {
			domain: signedZone,
			owner:  "@",
			settings: fmt.Sprintf(`{"server":%q,"tsig_key_name":%q,"tsig_secret":%q}`,
				testServer(), testTSIGKeyName, testTSIGSecret),
			ip: netip.MustParseAddr("10.20.30.40"),
		},
		"update without TSIG": {
			domain:   "open.com",
			owner:    testOwner,
			settings: fmt.Sprintf(`{"server":%q}`, testServer()),
			ip:       netip.MustParseAddr("1.1.1.1"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, err := New(json.RawMessage(testCase.settings), testCase.domain,
				testCase.owner, ipversion.IP4or6, netip.Prefix{})
			require.NoError(t, err)

			newIP, err := provider.Update(context.Background(), nil, testCase.ip)
			require.NoError(t, err)
			assert.Equal(t, testCase.ip, newIP)

			// Query the server to confirm the record was really written.
			resolved := resolve(t, provider.BuildDomainName(), testCase.ip.Is6())
			assert.Equal(t, testCase.ip, resolved)
		})
	}
}

func Test_integration_Update_badTSIGSecret(t *testing.T) {
	t.Parallel()

	settings := fmt.Sprintf(`{"server":%q,"tsig_key_name":%q,"tsig_secret":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		testServer(), testTSIGKeyName)
	provider, err := New(json.RawMessage(settings), signedZone, testOwner,
		ipversion.IP4or6, netip.Prefix{})
	require.NoError(t, err)

	_, err = provider.Update(context.Background(), nil, netip.MustParseAddr("3.3.3.3"))
	require.Error(t, err)
}

func Test_integration_Update_unsignedRefused(t *testing.T) {
	t.Parallel()

	// example.com only accepts signed updates.
	settings := fmt.Sprintf(`{"server":%q}`, testServer())
	provider, err := New(json.RawMessage(settings), signedZone, "refused",
		ipversion.IP4or6, netip.Prefix{})
	require.NoError(t, err)

	_, err = provider.Update(context.Background(), nil, netip.MustParseAddr("4.4.4.4"))
	require.ErrorIs(t, err, errors.ErrBadRequest)
}

func Test_integration_Update_unknownZone(t *testing.T) {
	t.Parallel()

	settings := fmt.Sprintf(`{"server":%q,"tsig_key_name":%q,"tsig_secret":%q}`,
		testServer(), testTSIGKeyName, testTSIGSecret)
	provider, err := New(json.RawMessage(settings), "unknown-zone.com", testOwner,
		ipversion.IP4or6, netip.Prefix{})
	require.NoError(t, err)

	_, err = provider.Update(context.Background(), nil, netip.MustParseAddr("6.6.6.6"))
	require.Error(t, err)
}

func resolve(t *testing.T, domainName string, ipv6 bool) (ip netip.Addr) {
	t.Helper()

	recordType := dns.TypeA
	if ipv6 {
		recordType = dns.TypeAAAA
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domainName), recordType)

	client := &dns.Client{Net: "tcp"}
	response, _, err := client.ExchangeContext(context.Background(), message, testServer())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, response.Rcode)
	require.Len(t, response.Answer, 1)

	switch record := response.Answer[0].(type) {
	case *dns.A:
		ip, _ = netip.AddrFromSlice(record.A.To4())
	case *dns.AAAA:
		ip, _ = netip.AddrFromSlice(record.AAAA)
	default:
		t.Fatalf("unexpected record type %T", record)
	}
	return ip
}
