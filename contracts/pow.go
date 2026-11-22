package contracts

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
)

// PoWInput is the text that the proof of work hashes.
func PoWInput(challengeID, token, nonce string) []byte {
	return []byte(challengeID + ":" + token + ":" + nonce)
}

// LeadingZeroBits counts the zero bits at the start of the SHA-256 hash of
// the proof of work input.
func LeadingZeroBits(challengeID, token, nonce string) int {
	sum := sha256.Sum256(PoWInput(challengeID, token, nonce))
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// CheckPoW reports whether nonce solves the challenge at the given difficulty.
// The nonce must be a canonical decimal number, as the schema requires.
func CheckPoW(challengeID, token, nonce string, difficultyBits int) bool {
	if _, err := strconv.ParseUint(nonce, 10, 64); err != nil {
		return false
	}
	return LeadingZeroBits(challengeID, token, nonce) >= difficultyBits
}

// SolvePoW returns the smallest nonce that solves the challenge. The time it
// takes grows about twice for each extra bit of difficulty.
func SolvePoW(challengeID, token string, difficultyBits int) string {
	for n := uint64(0); ; n++ {
		nonce := strconv.FormatUint(n, 10)
		if LeadingZeroBits(challengeID, token, nonce) >= difficultyBits {
			return nonce
		}
	}
}
