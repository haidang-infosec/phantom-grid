package spa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"time"
)

// TOTP generates a Time-based One-Time Password
func TOTP(secret []byte, timeStep int, timestamp int64) uint32 {
	// Calculate time counter
	counter := uint64(timestamp / int64(timeStep))

	// HMAC-SHA1
	mac := hmac.New(sha1.New, secret)
	binary.Write(mac, binary.BigEndian, counter)
	hash := mac.Sum(nil)

	// Dynamic truncation (RFC 4226)
	offset := hash[19] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Return 6-digit code
	return code % 1000000
}

// GenerateTOTP generates TOTP for current time
func GenerateTOTP(secret []byte, timeStep int) uint32 {
	return TOTP(secret, timeStep, time.Now().Unix())
}

// ValidateTOTP validates TOTP with tolerance
func ValidateTOTP(secret []byte, timeStep, tolerance int, receivedTOTP uint32) bool {
	currentTime := time.Now().Unix()
	currentStep := currentTime / int64(timeStep)

	// Check current step and ±tolerance steps
	for i := -tolerance; i <= tolerance; i++ {
		step := currentStep + int64(i)
		expectedTOTP := TOTP(secret, timeStep, step*int64(timeStep))
		if expectedTOTP == receivedTOTP {
			return true
		}
	}

	return false
}

// GetTOTPTimeWindow returns the time window for a given TOTP
func GetTOTPTimeWindow(timeStep int, timestamp int64) (start, end int64) {
	step := timestamp / int64(timeStep)
	start = step * int64(timeStep)
	end = start + int64(timeStep)
	return start, end
}

