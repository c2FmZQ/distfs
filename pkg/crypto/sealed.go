// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"crypto/mlkem"
	"encoding/binary"
	"fmt"
	"time"
)

// SealRequest encrypts and signs a request payload.
func SealRequest(serverPK *mlkem.EncapsulationKey768, clientSK *IdentityKey, payload []byte) ([]byte, error) {
	// 1. Prepare inner payload: [Timestamp][Signature][JSON]
	ts := time.Now().UnixNano()
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))

	// Data to sign: [Timestamp][JSON]
	toSign := make([]byte, 8+len(payload))
	copy(toSign[0:8], tsBytes)
	copy(toSign[8:], payload)
	sig := clientSK.Sign(toSign)

	// Inner: [Timestamp][Signature][Payload]
	inner := make([]byte, 8+len(sig)+len(payload))
	copy(inner[0:8], tsBytes)
	copy(inner[8:8+len(sig)], sig)
	copy(inner[8+len(sig):], payload)

	// 2. Encapsulate for server
	sharedSecret, kemCT := Encapsulate(serverPK)

	// 3. Encrypt inner with shared secret (DEM)
	demCT, err := EncryptDEM(sharedSecret, inner)
	if err != nil {
		return nil, fmt.Errorf("dem encrypt failed: %w", err)
	}

	// Result: [KEM CT][DEM CT]
	result := make([]byte, len(kemCT)+len(demCT))
	copy(result[0:len(kemCT)], kemCT)
	copy(result[len(kemCT):], demCT)

	return result, nil
}

// OpenRequest decrypts and verifies a sealed request.
func OpenRequest(serverSK *mlkem.DecapsulationKey768, clientPK []byte, sealed []byte) (int64, []byte, []byte, error) {
	kemSize := mlkem.CiphertextSize768
	if len(sealed) < kemSize {
		return 0, nil, nil, fmt.Errorf("sealed request too short")
	}

	kemCT := sealed[:kemSize]
	demCT := sealed[kemSize:]

	// 1. Decapsulate
	sharedSecret, err := serverSK.Decapsulate(kemCT)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("decapsulate failed: %w", err)
	}

	// 2. Decrypt DEM
	inner, err := DecryptDEM(sharedSecret, demCT)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("dem decrypt failed: %w", err)
	}

	if len(inner) < 8+64 { // ts(8) + ed25519 sig(64)
		return 0, nil, nil, fmt.Errorf("decrypted payload too short")
	}

	// 3. Parse Inner
	ts := int64(binary.BigEndian.Uint64(inner[0:8]))
	sig := inner[8 : 8+64]
	payload := inner[8+64:]

	// 4. Verify Signature
	toVerify := make([]byte, 8+len(payload))
	copy(toVerify[0:8], inner[0:8])
	copy(toVerify[8:], payload)
	if !VerifySignature(clientPK, toVerify, sig) {
		return 0, nil, nil, fmt.Errorf("invalid signature")
	}

	return ts, payload, sharedSecret, nil
}

// OpenRequestSymmetric decrypts a sealed request using a pre-shared key (Session Memoization).
func OpenRequestSymmetric(sharedSecret []byte, clientPK []byte, sealed []byte) (int64, []byte, error) {
	kemSize := mlkem.CiphertextSize768
	if len(sealed) < kemSize {
		return 0, nil, fmt.Errorf("sealed request too short")
	}

	// In memoized mode, the KEM CT is present (sent by client) but ignored by server
	// because we already have the shared secret.
	demCT := sealed[kemSize:]

	// 1. Decrypt DEM
	inner, err := DecryptDEM(sharedSecret, demCT)
	if err != nil {
		return 0, nil, fmt.Errorf("dem decrypt failed: %w", err)
	}

	if len(inner) < 8+64 {
		return 0, nil, fmt.Errorf("decrypted payload too short")
	}

	// 2. Parse Inner
	ts := int64(binary.BigEndian.Uint64(inner[0:8]))
	sig := inner[8 : 8+64]
	payload := inner[8+64:]

	// 3. Verify Signature
	toVerify := make([]byte, 8+len(payload))
	copy(toVerify[0:8], inner[0:8])
	copy(toVerify[8:], payload)
	if !VerifySignature(clientPK, toVerify, sig) {
		return 0, nil, fmt.Errorf("invalid signature")
	}

	return ts, payload, nil
}

// SealResponse encrypts and signs a response payload for a specific client.
func SealResponse(clientPK *mlkem.EncapsulationKey768, serverSK *IdentityKey, payload []byte) ([]byte, error) {
	// 1. Prepare inner payload: [Timestamp][Signature][JSON]
	ts := time.Now().UnixNano()
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))

	// Data to sign: [Timestamp][JSON]
	toSign := make([]byte, 8+len(payload))
	copy(toSign[0:8], tsBytes)
	copy(toSign[8:], payload)
	sig := serverSK.Sign(toSign)

	// Inner: [Timestamp][Signature][Payload]
	inner := make([]byte, 8+len(sig)+len(payload))
	copy(inner[0:8], tsBytes)
	copy(inner[8:8+len(sig)], sig)
	copy(inner[8+len(sig):], payload)

	// 2. Encapsulate for client
	sharedSecret, kemCT := Encapsulate(clientPK)

	// 3. Encrypt inner with shared secret (DEM)
	demCT, err := EncryptDEM(sharedSecret, inner)
	if err != nil {
		return nil, fmt.Errorf("dem encrypt failed: %w", err)
	}

	// Result: [KEM CT][DEM CT]
	result := make([]byte, len(kemCT)+len(demCT))
	copy(result[0:len(kemCT)], kemCT)
	copy(result[len(kemCT):], demCT)

	return result, nil
}

// OpenResponse decrypts and verifies a sealed response.
func OpenResponse(clientSK *mlkem.DecapsulationKey768, serverPK []byte, sealed []byte) (int64, []byte, error) {
	kemSize := mlkem.CiphertextSize768
	if len(sealed) < kemSize {
		return 0, nil, fmt.Errorf("sealed response too short")
	}

	kemCT := sealed[:kemSize]
	demCT := sealed[kemSize:]

	// 1. Decapsulate
	sharedSecret, err := clientSK.Decapsulate(kemCT)
	if err != nil {
		return 0, nil, fmt.Errorf("decapsulate failed: %w", err)
	}

	// 2. Decrypt DEM
	inner, err := DecryptDEM(sharedSecret, demCT)
	if err != nil {
		return 0, nil, fmt.Errorf("dem decrypt failed: %w", err)
	}

	if len(inner) < 8+64 { // ts(8) + sig(64)
		return 0, nil, fmt.Errorf("decrypted response too short")
	}

	// 3. Parse Inner
	ts := int64(binary.BigEndian.Uint64(inner[0:8]))
	sig := inner[8 : 8+64]
	payload := inner[8+64:]

	// 4. Verify Signature
	toVerify := make([]byte, 8+len(payload))
	copy(toVerify[0:8], inner[0:8])
	copy(toVerify[8:], payload)
	if !VerifySignature(serverPK, toVerify, sig) {
		return 0, nil, fmt.Errorf("invalid server signature")
	}

	return ts, payload, nil
}
