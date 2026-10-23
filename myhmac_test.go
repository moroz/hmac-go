package myhmac_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"myhmac"
	"strings"
	"testing"
)

type example struct {
	// name is a human-readable name of the test example.
	name string

	// key is the HMAC key (K), hex-encoded.
	key string

	// text is the message to be authenticated, hex-encoded.
	text string

	// expected is the correct return value of the
	// HMAC-SHA-256 function, hex-encoded.
	expected string
}

var examples = []example{
	{
		name: "Test Case 1",
		key:  strings.Repeat("0b", 20),
		text: "4869205468657265", // "Hi There"
		expected: "b0344c61d8db38535ca8afceaf0bf12b" +
			"881dc200c9833da726e9376c2e32cff7",
	},
	{
		name: "Test Case 2 (short key)",
		key:  "4a656665", // "Jefe"
		text: "7768617420646f2079612077616e7420" + // "what do ya want "
			"666f72206e6f7468696e673f", // "for nothing?"
		expected: "5bdcc146bf60754e6a042426089575c7" +
			"5a003f089d2739839dec58b964ec3843",
	},
	{
		name: "Test Case 3 (combined length of key and data > 64 bytes)",
		key:  strings.Repeat("aa", 20),
		text: strings.Repeat("dd", 50),
		expected: "773ea91e36800e46854db8ebd09181a7" +
			"2959098b3ef8c122d9635514ced565fe",
	},
	{
		name: "Test Case 4 (combined length of key and data > 64 bytes)",
		key: "0102030405060708090a0b0c0d0e0f10" +
			"111213141516171819",
		text: strings.Repeat("cd", 50),
		expected: "82558a389a443c0ea4cc819899f2083a" +
			"85f0faa3e578f8077a2e3ff46729665b",
	},
	{
		name: "Test Case 6 (key > 64 bytes)",
		key:  strings.Repeat("aa", 131),
		text: "54657374205573696e67204c61726765" +
			"72205468616e20426c6f636b2d53697a" +
			"65204b6579202d2048617368204b6579" +
			"204669727374",
		expected: "60e431591ee0b67f0d8a26aacbf5b77f" +
			"8e0bc6213728c5140546040f0ee37f54",
	},
	{
		name: "Test Case 7 (key and data both > 128 bytes)",
		key:  strings.Repeat("aa", 131),
		text: "54686973206973206120746573742075" +
			"73696e672061206c6172676572207468" +
			"616e20626c6f636b2d73697a65206b65" +
			"7920616e642061206c61726765722074" +
			"68616e20626c6f636b2d73697a652064" +
			"6174612e20546865206b6579206e6565" +
			"647320746f2062652068617368656420" +
			"6265666f7265206265696e6720757365" +
			"642062792074686520484d414320616c" +
			"676f726974686d2e",
		expected: "9b09ffa71b942fcb27635fbcd5b0e944" +
			"bfdc63644f0713938a7f51535c3a35e2",
	},
}

func mustDecodeHex(data string) []byte {
	bytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return bytes
}

func TestStandardLibraryBaseline(t *testing.T) {
	for _, example := range examples {
		t.Run(example.name, func(t *testing.T) {
			expected := mustDecodeHex(example.expected)

			mac := hmac.New(sha256.New, mustDecodeHex(example.key))
			mac.Write(mustDecodeHex(example.text))
			actual := mac.Sum(nil)

			// hmac.Equal compares the two slices in constant time
			// to prevent timing attacks.
			if !hmac.Equal(actual, expected) {
				t.Errorf(`Expected "%x", got "%x"`, expected, actual)
			}
		})
	}
}

func TestSHA256(t *testing.T) {
	for _, example := range examples {
		t.Run(example.name, func(t *testing.T) {
			key := mustDecodeHex(example.key)
			text := mustDecodeHex(example.text)
			expected := mustDecodeHex(example.expected)

			actual := myhmac.SHA256(key, text)

			if !hmac.Equal(actual, expected) {
				t.Errorf(`Expected "%x", got "%x"`, expected, actual)
			}
		})
	}
}
