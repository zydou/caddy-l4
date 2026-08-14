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
	"encoding/json"
	"fmt"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchTLS{})
}

// MatchTLS is able to match TLS connections. Its structure
// is different from the auto-generated documentation. This
// value should be a map of matcher names to their values.
type MatchTLS struct {
	MatchersRaw caddy.ModuleMap `json:"-" caddy:"namespace=tls.handshake_match"`

	// TelegramSecrets is a list of Telegram proxy secrets (hex format).
	// When provided, caddy-l4 verifies the HMAC in the ClientHello's
	// "random" field to distinguish Telegram FakeTLS from real browser TLS.
	// If HMAC verification succeeds, the connection is treated as NOT TLS
	// and will be forwarded to the non-TLS route (e.g. mtg).
	TelegramSecrets []string `json:"telegram_secrets,omitempty"`

	matchers   []caddytls.ConnectionMatcher
	logger     *zap.Logger
	secretKeys [][]byte // parsed from TelegramSecrets
}

// CaddyModule returns the Caddy module information.
func (*MatchTLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.tls",
		New: func() caddy.Module { return new(MatchTLS) },
	}
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (m *MatchTLS) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if secs, ok := raw["telegram_secrets"]; ok {
		if err := json.Unmarshal(secs, &m.TelegramSecrets); err != nil {
			return err
		}
		delete(raw, "telegram_secrets")
	}
	m.MatchersRaw = caddy.ModuleMap(raw)
	return nil
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m *MatchTLS) MarshalJSON() ([]byte, error) {
	result := make(map[string]json.RawMessage, len(m.MatchersRaw)+1)
	for k, v := range m.MatchersRaw {
		result[k] = v
	}
	if len(m.TelegramSecrets) > 0 {
		b, err := json.Marshal(m.TelegramSecrets)
		if err != nil {
			return nil, err
		}
		result["telegram_secrets"] = b
	}
	return json.Marshal(result)
}

// Provision sets up the handler.
func (m *MatchTLS) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	mods, err := ctx.LoadModule(m, "MatchersRaw")
	if err != nil {
		return fmt.Errorf("loading TLS matchers: %v", err)
	}
	for _, modIface := range mods.(map[string]any) {
		m.matchers = append(m.matchers, modIface.(caddytls.ConnectionMatcher))
	}

	// Parse Telegram secrets into HMAC keys
	for _, secret := range m.TelegramSecrets {
		key, err := parseTelegramSecret(secret)
		if err != nil {
			return fmt.Errorf("parsing Telegram secret: %v", err)
		}
		m.secretKeys = append(m.secretKeys, key)
	}

	if len(m.secretKeys) > 0 {
		m.logger.Info("Telegram FakeTLS HMAC detection enabled",
			zap.Int("num_secrets", len(m.secretKeys)),
		)
	}

	return nil
}

// Match returns true if the connection is a TLS handshake.
func (m *MatchTLS) Match(cx *layer4.Connection) (bool, error) {
	// read the header bytes
	const recordHeaderLen = 5
	hdr := make([]byte, recordHeaderLen)
	_, err := io.ReadFull(cx, hdr)
	if err != nil {
		return false, err
	}

	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return false, nil
	}

	// get length of the ClientHello message and read it
	//nolint:gosec // disable G602 // https://github.com/securego/gosec/issues/1406
	length := int(uint16(hdr[3])<<8 | uint16(hdr[4])) // ignoring version in hdr[1:3] - like https://github.com/inetaf/tcpproxy/blob/master/sni.go#L170
	rawHello := make([]byte, length)
	_, err = io.ReadFull(cx, rawHello)
	if err != nil {
		return false, err
	}

	// Keep a copy of the full ClientHello including TLS record headers.
	// Telegram FakeTLS computes its HMAC over the entire ClientHello
	// including record headers (see Telegram TlsInit), so the record
	// headers must be preserved for HMAC verification. rawHello (without
	// record headers) is still used for ClientHello parsing below.
	fullHello := make([]byte, 0, recordHeaderLen+len(rawHello))
	fullHello = append(fullHello, hdr...)
	fullHello = append(fullHello, rawHello...)

	// Ensure we have at least 4 bytes handshake header before parsing length.
	for len(rawHello) < 4 {
		hdr2 := make([]byte, recordHeaderLen)
		_, err := io.ReadFull(cx, hdr2)
		if err != nil {
			return false, err
		}

		if hdr2[0] != recordTypeHandshake {
			break
		}

		//nolint:gosec // disable G602 // https://github.com/securego/gosec/issues/1406
		length2 := int(uint16(hdr2[3])<<8 | uint16(hdr2[4]))
		if len(rawHello)+length2 > layer4.MaxMatchingBytes {
			return false, fmt.Errorf("TLS records too large: %d > %d", len(rawHello)+length2, layer4.MaxMatchingBytes)
		}

		body2 := make([]byte, length2)
		_, err = io.ReadFull(cx, body2)
		if err != nil {
			return false, err
		}

		fullHello = append(fullHello, hdr2...)
		fullHello = append(fullHello, body2...)
		rawHello = append(rawHello, body2...)
	}

	if len(rawHello) >= 4 && rawHello[0] == 1 {
		handshakeLen := int(uint32(rawHello[1])<<16 | uint32(rawHello[2])<<8 | uint32(rawHello[3]))

		if handshakeLen > layer4.MaxMatchingBytes {
			return false, fmt.Errorf("ClientHello too large: %d > %d", handshakeLen, layer4.MaxMatchingBytes)
		}

		totalNeeded := handshakeLen + 4

		for len(rawHello) < totalNeeded {
			hdr2 := make([]byte, recordHeaderLen)
			_, err := io.ReadFull(cx, hdr2)
			if err != nil {
				return false, err
			}

			if hdr2[0] != recordTypeHandshake {
				break
			}

			//nolint:gosec // disable G602 // https://github.com/securego/gosec/issues/1406
			length2 := int(uint16(hdr2[3])<<8 | uint16(hdr2[4]))

			if len(rawHello)+length2 > layer4.MaxMatchingBytes {
				return false, fmt.Errorf("TLS records too large: %d > %d", len(rawHello)+length2, layer4.MaxMatchingBytes)
			}

			body2 := make([]byte, length2)
			_, err = io.ReadFull(cx, body2)
			if err != nil {
				return false, err
			}

			fullHello = append(fullHello, hdr2...)
			fullHello = append(fullHello, body2...)
			rawHello = append(rawHello, body2...)
		}
	}

	// Check if this is Telegram's FakeTLS by verifying the HMAC.
	// If HMAC verification succeeds, it's Telegram traffic → NOT real TLS.
	if len(m.secretKeys) > 0 && tryVerifyFakeTLS(fullHello, m.secretKeys, m.logger) {
                m.logger.Info("detected Telegram FakeTLS via HMAC, forwarding to:",
			zap.String("remote", cx.RemoteAddr().String()),
		)
		return false, nil
	}

	// parse the ClientHello
	chi := parseRawClientHello(rawHello)
	chi.Conn = cx

	// also add values to the replacer
	repl := cx.Replacer()
	repl.Set(tlsServerNameReplKey, chi.ServerName)
	repl.Set(tlsVersionReplKey, caddytls.ProtocolName(chi.Version))

	for _, matcher := range m.matchers {
		// TODO: even though we have more data than the standard lib's
		// ClientHelloInfo lets us fill, the matcher modules we use do
		// not accept our own type; but the advantage of this is that
		// we can reuse TLS connection matchers from the tls app - but
		// it would be nice if we found a way to give matchers all
		// the information
		if !matcher.Match(&chi.ClientHelloInfo) {
			return false, nil
		}
	}

	m.logger.Debug("matched",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.String("server_name", chi.ServerName),
	)

	return true, nil
}

// UnmarshalCaddyfile sets up the MatchTLS from Caddyfile tokens. Syntax:
//
//	tls {
//		matcher [<args...>]
//		matcher [<args...>]
//	}
//	tls matcher [<args...>]
//	tls
//
// With Telegram secrets for FakeTLS detection:
//
//	tls {
//		telegram_secrets <secret1> [<secret2> ...]
//	}
func (m *MatchTLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	// First, collect all tokens in this block for nested matcher parsing
	tokensByMatcherName := make(map[string][]caddyfile.Token)
	var telegramSecrets []string

	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		token := d.Val()
		if token == "telegram_secrets" {
			// Collect all remaining args on this line as secrets
			for d.NextArg() {
				telegramSecrets = append(telegramSecrets, d.Val())
			}
		} else {
			// It's a nested matcher - collect its tokens
			tokensByMatcherName[token] = append(tokensByMatcherName[token], d.NextSegment()...)
		}
	}

	m.TelegramSecrets = telegramSecrets

	// Parse nested matchers if any
	if len(tokensByMatcherName) > 0 {
		matcherMap := make(map[string]caddytls.ConnectionMatcher)
		for matcherName, tokens := range tokensByMatcherName {
			dd := caddyfile.NewDispenser(tokens)
			dd.Next() // consume wrapper name

			mod, err := caddy.GetModule("tls.handshake_match." + matcherName)
			if err != nil {
				return fmt.Errorf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return fmt.Errorf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(dd.NewFromNextSegment())
			if err != nil {
				return err
			}
			cm, ok := unm.(caddytls.ConnectionMatcher)
			if !ok {
				return fmt.Errorf("matcher module '%s' is not a connection matcher", matcherName)
			}
			matcherMap[matcherName] = cm
		}

		matcherSet := make(caddy.ModuleMap)
		for name, matcher := range matcherMap {
			jsonBytes, err := json.Marshal(matcher)
			if err != nil {
				return fmt.Errorf("marshaling %T matcher: %v", matcher, err)
			}
			matcherSet[name] = jsonBytes
		}
		m.MatchersRaw = matcherSet
	} else {
		// No nested matchers - set empty map to avoid null
		m.MatchersRaw = make(caddy.ModuleMap)
	}

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchTLS)(nil)
	_ caddy.Provisioner     = (*MatchTLS)(nil)
	_ caddyfile.Unmarshaler = (*MatchTLS)(nil)
	_ json.Marshaler        = (*MatchTLS)(nil)
	_ json.Unmarshaler      = (*MatchTLS)(nil)
)

// Replacer prefixes and keys; names of context variables
const (
	tlsReplPrefix = layer4.AppReplPrefix + "tls."

	tlsServerNameReplKey = tlsReplPrefix + "server_name"
	tlsVersionReplKey    = tlsReplPrefix + "version"
)

// ParseCaddyfileNestedMatcherSet parses the Caddyfile tokens for a nested
// matcher set, and returns its raw module map value.
func ParseCaddyfileNestedMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]caddytls.ConnectionMatcher)

	tokensByMatcherName := make(map[string][]caddyfile.Token)
	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		matcherName := d.Val()
		tokensByMatcherName[matcherName] = append(tokensByMatcherName[matcherName], d.NextSegment()...)
	}

	for matcherName, tokens := range tokensByMatcherName {
		dd := caddyfile.NewDispenser(tokens)
		dd.Next() // consume wrapper name

		mod, err := caddy.GetModule("tls.handshake_match." + matcherName)
		if err != nil {
			return nil, d.Errf("getting matcher module '%s': %v", matcherName, err)
		}
		unm, ok := mod.New().(caddyfile.Unmarshaler)
		if !ok {
			return nil, d.Errf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
		}
		err = unm.UnmarshalCaddyfile(dd.NewFromNextSegment())
		if err != nil {
			return nil, err
		}
		cm, ok := unm.(caddytls.ConnectionMatcher)
		if !ok {
			return nil, fmt.Errorf("matcher module '%s' is not a connection matcher", matcherName)
		}
		matcherMap[matcherName] = cm
	}

	matcherSet := make(caddy.ModuleMap)
	for name, matcher := range matcherMap {
		jsonBytes, err := json.Marshal(matcher)
		if err != nil {
			return nil, fmt.Errorf("marshaling %T matcher: %v", matcher, err)
		}
		matcherSet[name] = jsonBytes
	}

	return matcherSet, nil
}
