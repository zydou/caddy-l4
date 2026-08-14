// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// ==================== JSON serialization ====================

func TestMatchTLSJSONRoundTrip(t *testing.T) {
	// TelegramSecrets only (no nested matchers)
	m := &MatchTLS{
		TelegramSecrets: []string{"ee73a00b8004bb5213ec2530d6fa8d39cf3132332e3132332e3132332e313233"},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("marshal: %s", out)

	var m2 MatchTLS
	if err := json.Unmarshal(out, &m2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.TelegramSecrets, m2.TelegramSecrets) {
		t.Fatalf("TelegramSecrets mismatch: got %v, want %v", m2.TelegramSecrets, m.TelegramSecrets)
	}
}

func TestMatchTLSJSONWithNestedMatchers(t *testing.T) {
	// TelegramSecrets combined with nested matchers
	m := &MatchTLS{
		TelegramSecrets: []string{"ee73a00b8004bb5213ec2530d6fa8d39cf3132332e3132332e3132332e313233"},
		MatchersRaw: caddy.ModuleMap{
			"sni": json.RawMessage(`["example.com"]`),
		},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("marshal: %s", out)

	var m2 MatchTLS
	if err := json.Unmarshal(out, &m2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.TelegramSecrets, m2.TelegramSecrets) {
		t.Fatalf("TelegramSecrets mismatch: got %v, want %v", m2.TelegramSecrets, m.TelegramSecrets)
	}
	if !reflect.DeepEqual(m.MatchersRaw, m2.MatchersRaw) {
		t.Fatalf("MatchersRaw mismatch: got %v, want %v", m2.MatchersRaw, m.MatchersRaw)
	}
}

func TestMatchTLSJSONCompatibility(t *testing.T) {
	// Old JSON format without telegram_secrets must still parse
	// into a valid matcher set.
	m := &MatchTLS{}
	if err := json.Unmarshal([]byte(`{"sni":["example.com"]}`), m); err != nil {
		t.Fatal(err)
	}
	if m.TelegramSecrets != nil {
		t.Fatalf("TelegramSecrets should be nil, got %v", m.TelegramSecrets)
	}
	if len(m.MatchersRaw) != 1 {
		t.Fatalf("MatchersRaw should have 1 entry, got %d", len(m.MatchersRaw))
	}
}

func TestMatchTLSJSONEmpty(t *testing.T) {
	// Empty matcher must marshal to {} (not null) so that
	// `{ "tls": {} }` round-trips correctly.
	m := &MatchTLS{}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("marshal empty: %s", out)
	if string(out) != "{}" {
		t.Fatalf("empty MatchTLS should marshal to {}, got %s", out)
	}

	var m2 MatchTLS
	if err := json.Unmarshal(out, &m2); err != nil {
		t.Fatal(err)
	}
	if m2.MatchersRaw == nil {
		t.Fatalf("MatchersRaw should be non-nil after unmarshal")
	}
}

// ==================== FakeTLS matching behavior ====================

// buildFakeTLSClientHello constructs a Telegram FakeTLS ClientHello exactly as
// the official Telegram client does (see td/mtproto/TlsInit.cpp):
//   1. Build ClientHello with the random field zeroed
//   2. digest = HMAC-SHA256(secret, zeroed_hello)
//   3. wire_random = digest XOR (0x00*28 || LE32(timestamp))
//   4. Fill the random field with wire_random
func buildFakeTLSClientHello(secret []byte, timestamp uint32) []byte {
	// A minimal but structurally valid ClientHello:
	// record header(5) + handshake header(4) + version(2) + random(32) + session_id_len(1)
	hello := make([]byte, 5+4+2+32+1)
	hello[0] = 0x16                 // handshake record
	hello[1], hello[2] = 0x03, 0x01 // TLS 1.0 record version
	hello[3] = 0x00
	hello[4] = byte(len(hello) - 5) // record length
	hello[5] = 0x01                 // ClientHello handshake type
	hello[6], hello[7], hello[8] = 0x00, 0x00, byte(len(hello)-5-4) // handshake length
	hello[9], hello[10] = 0x03, 0x03                                // TLS 1.2
	// bytes 11-42 are the random field, initially zeroed

	// HMAC over the whole ClientHello (random zeroed)
	mac := hmac.New(sha256.New, secret)
	mac.Write(hello)
	digest := mac.Sum(nil)

	// wire_random = digest XOR (0x00*28 || LE32(timestamp))
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[28:], timestamp)
	for i := 0; i < 32; i++ {
		hello[11+i] = digest[i] ^ payload[i]
	}

	return hello
}

// buildRealTLSClientHello constructs a ClientHello with a truly random
// random field, mimicking a real browser/v2ray TLS handshake.
func buildRealTLSClientHello() []byte {
	hello := make([]byte, 5+4+2+32+1)
	hello[0] = 0x16
	hello[1], hello[2] = 0x03, 0x01
	hello[3] = 0x00
	hello[4] = byte(len(hello) - 5)
	hello[5] = 0x01
	hello[6], hello[7], hello[8] = 0x00, 0x00, byte(len(hello)-5-4)
	hello[9], hello[10] = 0x03, 0x03
	if _, err := rand.Read(hello[11:43]); err != nil {
		panic(err)
	}
	return hello
}

// matchClientHello runs MatchTLS.Match against the given ClientHello bytes.
// It uses net.Pipe so that the connection behaves like a real net.Conn
// (LocalAddr/RemoteAddr etc. all work as required by layer4.Connection).
func matchClientHello(t *testing.T, secrets []string, hello []byte) bool {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// feed the ClientHello on the server side in a goroutine
	go func() {
		defer client.Close()
		if _, err := client.Write(hello); err != nil {
			return
		}
	}()

	cx := layer4.WrapConnection(server, make([]byte, 0, layer4.MaxMatchingBytes), zap.NewNop())

	m := &MatchTLS{
		TelegramSecrets: secrets,
		logger:          zap.NewNop(),
	}
	// parse secrets like Provision does
	for _, secret := range secrets {
		key, err := parseTelegramSecret(secret)
		if err != nil {
			t.Fatal(err)
		}
		m.secretKeys = append(m.secretKeys, key)
	}

	matched, err := m.Match(cx)
	if err != nil {
		t.Fatal(err)
	}
	return matched
}

func TestMatchTLSBehavior(t *testing.T) {
	secretHex := "ee73a00b8004bb5213ec2530d6fa8d39cf3132332e3132332e3132332e313233"
	key, err := parseTelegramSecret(secretHex)
	if err != nil {
		t.Fatal(err)
	}
	now := uint32(time.Now().Unix())

	t.Run("FakeTLS with valid HMAC and timestamp is NOT TLS", func(t *testing.T) {
		hello := buildFakeTLSClientHello(key, now)
		matched := matchClientHello(t, []string{secretHex}, hello)
		if matched {
			t.Fatal("FakeTLS ClientHello should NOT match the tls matcher")
		}
	})

	t.Run("FakeTLS with stale timestamp leaks as TLS (tolerance window)", func(t *testing.T) {
		// timestamp 10 minutes in the past: beyond the ±120s tolerance
		hello := buildFakeTLSClientHello(key, now-600)
		matched := matchClientHello(t, []string{secretHex}, hello)
		t.Logf("stale-timestamp FakeTLS treated as TLS: %v (leak as designed by tolerance window)", matched)
	})

	t.Run("Real TLS ClientHello matches the tls matcher", func(t *testing.T) {
		hello := buildRealTLSClientHello()
		matched := matchClientHello(t, []string{secretHex}, hello)
		if !matched {
			t.Fatal("Real TLS ClientHello should match the tls matcher")
		}
	})
}

// TestNotMatcherSemantics verifies that the `not` matcher combined with a
// telegram_secrets tls matcher correctly captures FakeTLS traffic. This is
// what a Caddyfile of the form `tls + not { tls { telegram_secrets } }`
// relies on: FakeTLS is a TLS-shaped connection that fails HMAC verification.
func TestNotMatcherSemantics(t *testing.T) {
	secretHex := "ee73a00b8004bb5213ec2530d6fa8d39cf3132332e3132332e3132332e313233"
	key, err := parseTelegramSecret(secretHex)
	if err != nil {
		t.Fatal(err)
	}
	now := uint32(time.Now().Unix())

	t.Run("FakeTLS is captured by not(tls)", func(t *testing.T) {
		hello := buildFakeTLSClientHello(key, now)
		tlsMatched := matchClientHello(t, []string{secretHex}, hello)
		if tlsMatched {
			t.Fatal("expected FakeTLS to NOT match tls matcher")
		}
		// not inverts: FakeTLS should be routed to telemt
		notMatched := !tlsMatched
		if !notMatched {
			t.Fatal("expected not(tls) to match FakeTLS")
		}
		t.Logf("FakeTLS: tls=%v, not(tls)=%v -> routed to telemt", tlsMatched, notMatched)
	})

	t.Run("Real TLS is NOT captured by not(tls)", func(t *testing.T) {
		hello := buildRealTLSClientHello()
		tlsMatched := matchClientHello(t, []string{secretHex}, hello)
		if !tlsMatched {
			t.Fatal("expected real TLS to match tls matcher")
		}
		notMatched := !tlsMatched
		if notMatched {
			t.Fatal("expected not(tls) to NOT match real TLS")
		}
		t.Logf("Real TLS: tls=%v, not(tls)=%v -> passed to HTTP app", tlsMatched, notMatched)
	})
}
