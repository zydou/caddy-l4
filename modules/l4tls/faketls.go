// Copyright 2024 Telegram FakeTLS Detector
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// timeSkewTolerance is the allowed time difference (in seconds) between the
// client's timestamp and the server's clock. Telegram uses ±120 seconds.
const timeSkewTolerance = 120

// verifyTelegramFakeTLS checks if the given ClientHello bytes are a valid
// Telegram MTProxy FakeTLS handshake by verifying the HMAC in the "random" field.
//
// Telegram FakeTLS protocol:
// Client:
//   1. Build ClientHello with bytes 11-42 (random field) zeroed
//   2. digest = HMAC-SHA256(secret[0:16], zeroed_ClientHello)
//   3. wire_random = digest XOR (0x00*28 || LE32(timestamp))
//
// Server verification:
//   1. Zero out bytes 11-42 of received ClientHello
//   2. server_digest = HMAC-SHA256(secret[0:16], zeroed_ClientHello)
//   3. xor_result = received_random XOR server_digest
//   4. If xor_result[0:28] == 0x00 AND |LE32(xor_result[28:32]) - now| < 120s → valid
//
// This is cryptographically impossible to forge without the secret key.
func verifyTelegramFakeTLS(rawHello []byte, secretKey []byte, logger *zap.Logger) bool {
	const (
		randomOffset = 11 // 5 (record header) + 1 (handshake type) + 3 (length) + 2 (version)
		randomLen    = 32
	)

	if len(rawHello) < randomOffset+randomLen {
		logger.Debug("FakeTLS: ClientHello too short",
			zap.Int("len", len(rawHello)),
		)
		return false
	}

	// Extract the received random field
	receivedRandom := rawHello[randomOffset : randomOffset+randomLen]

	// Create a copy with the random field zeroed
	zeroedHello := make([]byte, len(rawHello))
	copy(zeroedHello, rawHello)
	for i := randomOffset; i < randomOffset+randomLen; i++ {
		zeroedHello[i] = 0
	}

	// Compute HMAC-SHA256(secret, zeroed_ClientHello)
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(zeroedHello)
	serverDigest := mac.Sum(nil)

	// XOR the received random with the server digest
	// For valid FakeTLS: result should be 0x00*28 || LE32(timestamp)
	xorResult := make([]byte, randomLen)
	for i := 0; i < randomLen; i++ {
		xorResult[i] = receivedRandom[i] ^ serverDigest[i]
	}

	// Check if first 28 bytes are all zero
	for i := 0; i < 28; i++ {
		if xorResult[i] != 0 {
			return false
		}
	}

	// Extract timestamp from last 4 bytes (little-endian uint32)
	timestamp := uint32(xorResult[28]) |
		uint32(xorResult[29])<<8 |
		uint32(xorResult[30])<<16 |
		uint32(xorResult[31])<<24

	now := uint32(time.Now().Unix())
	diff := int64(now) - int64(timestamp)
	if diff < 0 {
		diff = -diff
	}

	if diff > timeSkewTolerance {
		logger.Debug("FakeTLS: timestamp out of tolerance",
			zap.Uint32("timestamp", timestamp),
			zap.Uint32("now", now),
			zap.Int64("diff", diff),
		)
		return false
	}

	return true
}

// tryVerifyFakeTLS tries all provided secret keys. If any key produces
// a valid HMAC, the ClientHello is Telegram FakeTLS.
func tryVerifyFakeTLS(rawHello []byte, secretKeys [][]byte, logger *zap.Logger) bool {
	for i, key := range secretKeys {
		if verifyTelegramFakeTLS(rawHello, key, logger) {
			logger.Info("Telegram FakeTLS verified via HMAC",
				zap.Int("key_index", i),
			)
			return true
		}
	}
	return false
}

// parseTelegramSecret parses a Telegram FakeTLS proxy secret and extracts
// the 16-byte HMAC key.
//
// Only supports "ee" prefix (TLS emulation / FakeTLS mode):
//   "ee" + 32_hex_chars + domain_hex
//
// The key is bytes 1-16 (after the 0xee prefix).
func parseTelegramSecret(secret string) ([]byte, error) {
	data, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	// Only support "ee" prefix (FakeTLS / TLS emulation mode)
	if len(data) < 17 {
		return nil, fmt.Errorf("secret too short: %d bytes (need >= 17)", len(data))
	}
	if data[0] != 0xee {
		return nil, fmt.Errorf("only 'ee' (FakeTLS) mode is supported, got: 0x%02x", data[0])
	}

	return data[1:17], nil
}
