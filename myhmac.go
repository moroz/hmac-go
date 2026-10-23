package myhmac

import (
	"crypto/sha256"
	"slices"
)

const (
	ipad = 0x36
	opad = 0x5C
)

func SHA256(key, message []byte) []byte {
	innerKey := padKey(key, ipad)
	outerKey := padKey(key, opad)
	innerHash := sha256.Sum256(
		slices.Concat(innerKey, message),
	)
	outerHash := sha256.Sum256(
		slices.Concat(outerKey, innerHash[:]),
	)

	return outerHash[:]
}

func padKey(key []byte, mask byte) []byte {
	buffer := make([]byte, sha256.BlockSize)

	if len(key) > sha256.BlockSize {
		hashed := sha256.Sum256(key)
		key = hashed[:]
	}

	copy(buffer, key)

	for i := range buffer {
		buffer[i] ^= mask
	}

	return buffer
}
