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
	sigSize := SignatureSize()
	inner := make([]byte, 8+sigSize+len(payload))
	copy(inner[0:8], tsBytes)
	copy(inner[8:8+sigSize], sig)
	copy(inner[8+sigSize:], payload)

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

	sigSize := SignatureSize()
	if len(inner) < 8+sigSize {
		return 0, nil, nil, fmt.Errorf("decrypted payload too short")
	}

	// 3. Parse Inner
	ts := int64(binary.BigEndian.Uint64(inner[0:8]))
	sig := inner[8 : 8+sigSize]
	payload := inner[8+sigSize:]

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

	sigSize := SignatureSize()
	if len(inner) < 8+sigSize {
		return 0, nil, fmt.Errorf("decrypted payload too short")
	}

	// 2. Parse Inner
	ts := int64(binary.BigEndian.Uint64(inner[0:8]))
	sig := inner[8 : 8+sigSize]
	payload := inner[8+sigSize:]

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
	sigSize := SignatureSize()
	inner := make([]byte, 8+sigSize+len(payload))
	copy(inner[0:8], tsBytes)
	copy(inner[8:8+sigSize], sig)
	copy(inner[8+sigSize:], payload)

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

	sigSize := SignatureSize()
	if len(inner) < 8+sigSize { // ts(8) + sig(sigSize)
		return 0, nil, fmt.Errorf("decrypted response too short")
	}

	// 3. Parse Inner
	ts := int64(binary.BigEndian.Uint64(inner[0:8]))
	sig := inner[8 : 8+sigSize]
	payload := inner[8+sigSize:]

	// 4. Verify Signature
	toVerify := make([]byte, 8+len(payload))
	copy(toVerify[0:8], inner[0:8])
	copy(toVerify[8:], payload)
	if !VerifySignature(serverPK, toVerify, sig) {
		return 0, nil, fmt.Errorf("invalid server signature")
	}

	return ts, payload, nil
}

// Seal performs authenticated encryption of a payload for a recipient's public key.
// It is intended for metadata like encrypted group names or keys.
func Seal(payload []byte, recipientPK *mlkem.EncapsulationKey768, nonce int64) ([]byte, error) {
	// 1. Encapsulate shared secret
	sharedSecret, kemCT := Encapsulate(recipientPK)

	// 2. Prepare inner: [Nonce][Payload]
	// Using nonce for replay protection if needed by caller
	inner := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(inner[0:8], uint64(nonce))
	copy(inner[8:], payload)

	// 3. Encrypt with shared secret (DEM)
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

// Unseal decrypts an authenticated payload using the recipient's private key.
func Unseal(sealed []byte, recipientSK *mlkem.DecapsulationKey768) ([]byte, error) {
	kemSize := mlkem.CiphertextSize768
	if len(sealed) < kemSize {
		return nil, fmt.Errorf("sealed data too short")
	}

	kemCT := sealed[:kemSize]
	demCT := sealed[kemSize:]

	// 1. Decapsulate shared secret
	sharedSecret, err := recipientSK.Decapsulate(kemCT)
	if err != nil {
		return nil, fmt.Errorf("decapsulate failed: %w", err)
	}

	// 2. Decrypt DEM
	inner, err := DecryptDEM(sharedSecret, demCT)
	if err != nil {
		return nil, fmt.Errorf("dem decrypt failed: %w", err)
	}

	if len(inner) < 8 {
		return nil, fmt.Errorf("decrypted data too short")
	}

	// Return payload (ignoring nonce, as it's for caller to verify if needed)
	return inner[8:], nil
}
