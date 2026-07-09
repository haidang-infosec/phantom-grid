package spa

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// SPAPacket represents a dynamic SPA packet
type SPAPacket struct {
	Version    uint8  // Protocol version (1 byte)
	Mode       uint8  // SPA mode: 0=static, 1=dynamic, 2=asymmetric (1 byte)
	Timestamp  int64  // Unix timestamp (8 bytes)
	TOTP       uint32 // TOTP nonce (4 bytes)
	ClientIP   net.IP // Client IP for Replay/Hijack protection (16 bytes)
	Signature  []byte // Ed25519 signature (64 bytes) or HMAC (32 bytes)
	RandomData []byte // Random padding for obfuscation (variable)
}

// Packet sizes
const (
	SPAPacketHeaderSizeV1 = 14 // Legacy Version 1
	SPAPacketHeaderSizeV2 = 30 // Version(1) + Mode(1) + Timestamp(8) + TOTP(4) + ClientIP(16)
	Ed25519SignatureSize = 64
	HMACSignatureSize   = 32
	MinRandomPadding     = 16
	MaxRandomPadding     = 64
)

// CreateAsymmetricPacket creates an Ed25519-signed SPA packet (Version 2)
func CreateAsymmetricPacket(privateKey ed25519.PrivateKey, totpSecret []byte, timeStep int, enableObfuscation bool, clientIP net.IP) ([]byte, error) {
	// Generate TOTP
	totp := GenerateTOTP(totpSecret, timeStep)
	timestamp := time.Now().Unix()

	// Ensure IP is 16 bytes
	ipBytes := clientIP.To16()
	if ipBytes == nil {
		ipBytes = net.IPv4zero.To16()
	}

	// Create packet header (Version 2)
	packet := make([]byte, SPAPacketHeaderSizeV2)
	packet[0] = 2 // Version 2
	packet[1] = 2 // Mode: Asymmetric
	binary.BigEndian.PutUint64(packet[2:10], uint64(timestamp))
	binary.BigEndian.PutUint32(packet[10:14], totp)
	copy(packet[14:30], ipBytes)

	// Add random padding for obfuscation
	var paddingSize int
	if enableObfuscation {
		// Generate random padding size
		randBytes := make([]byte, 1)
		rand.Read(randBytes)
		paddingSize = MinRandomPadding + int(randBytes[0])%(MaxRandomPadding-MinRandomPadding+1)
	} else {
		paddingSize = 0
	}

	if paddingSize > 0 {
		padding := make([]byte, paddingSize)
		if _, err := rand.Read(padding); err != nil {
			return nil, err
		}
		packet = append(packet, padding...)
	}

	// Sign the packet (header + padding)
	signature := ed25519.Sign(privateKey, packet)

	// Append signature
	packet = append(packet, signature...)

	return packet, nil
}

// CreateDynamicPacket creates an HMAC-signed SPA packet (Version 2)
func CreateDynamicPacket(hmacSecret []byte, totpSecret []byte, timeStep int, enableObfuscation bool, clientIP net.IP) ([]byte, error) {
	// Generate TOTP
	totp := GenerateTOTP(totpSecret, timeStep)
	timestamp := time.Now().Unix()

	// Ensure IP is 16 bytes
	ipBytes := clientIP.To16()
	if ipBytes == nil {
		ipBytes = net.IPv4zero.To16()
	}

	// Create packet header (Version 2)
	packet := make([]byte, SPAPacketHeaderSizeV2)
	packet[0] = 2 // Version 2
	packet[1] = 1 // Mode: Dynamic (HMAC)
	binary.BigEndian.PutUint64(packet[2:10], uint64(timestamp))
	binary.BigEndian.PutUint32(packet[10:14], totp)
	copy(packet[14:30], ipBytes)

	// Add random padding for obfuscation
	var paddingSize int
	if enableObfuscation {
		// Generate random padding size
		randBytes := make([]byte, 1)
		rand.Read(randBytes)
		paddingSize = MinRandomPadding + int(randBytes[0])%(MaxRandomPadding-MinRandomPadding+1)
	} else {
		paddingSize = 0
	}

	if paddingSize > 0 {
		padding := make([]byte, paddingSize)
		if _, err := rand.Read(padding); err != nil {
			return nil, err
		}
		packet = append(packet, padding...)
	}

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(packet)
	hmacValue := mac.Sum(nil)

	// Append HMAC
	packet = append(packet, hmacValue...)

	return packet, nil
}

// ParseSPAPacket parses a received SPA packet (Supports V1 and V2)
func ParseSPAPacket(data []byte) (*SPAPacket, error) {
	if len(data) < SPAPacketHeaderSizeV1 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	packet := &SPAPacket{
		Version: data[0],
		Mode:    data[1],
	}

	var headerSize int
	if packet.Version == 1 {
		headerSize = SPAPacketHeaderSizeV1
		packet.Timestamp = int64(binary.BigEndian.Uint64(data[2:10]))
		packet.TOTP = binary.BigEndian.Uint32(data[10:14])
		// V1 has no ClientIP
	} else if packet.Version == 2 {
		headerSize = SPAPacketHeaderSizeV2
		if len(data) < headerSize {
			return nil, fmt.Errorf("v2 packet too short: %d bytes", len(data))
		}
		packet.Timestamp = int64(binary.BigEndian.Uint64(data[2:10]))
		packet.TOTP = binary.BigEndian.Uint32(data[10:14])
		packet.ClientIP = net.IP(data[14:30])
	} else {
		return nil, fmt.Errorf("unsupported SPA version: %d", packet.Version)
	}

	// Determine signature size based on mode
	var signatureSize int
	switch packet.Mode {
	case 1: // Dynamic (HMAC)
		signatureSize = HMACSignatureSize
	case 2: // Asymmetric (Ed25519)
		signatureSize = Ed25519SignatureSize
	default:
		return nil, fmt.Errorf("unknown SPA mode: %d", packet.Mode)
	}

	// Extract signature and padding
	if len(data) < headerSize+signatureSize {
		return nil, fmt.Errorf("packet too short for signature: %d bytes", len(data))
	}

	// Padding is between header and signature
	paddingSize := len(data) - headerSize - signatureSize
	if paddingSize > 0 {
		packet.RandomData = data[headerSize : headerSize+paddingSize]
	}

	packet.Signature = data[len(data)-signatureSize:]

	return packet, nil
}

// VerifyAsymmetricPacket verifies Ed25519 signature
func VerifyAsymmetricPacket(publicKey ed25519.PublicKey, packet *SPAPacket, packetData []byte) bool {
	// Reconstruct signed data (header + padding, without signature)
	signedData := packetData[:len(packetData)-len(packet.Signature)]

	return ed25519.Verify(publicKey, signedData, packet.Signature)
}

// VerifyDynamicPacket verifies HMAC signature
func VerifyDynamicPacket(hmacSecret []byte, packet *SPAPacket, packetData []byte) bool {
	// Reconstruct signed data (header + padding, without signature)
	signedData := packetData[:len(packetData)-len(packet.Signature)]

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(signedData)
	expectedHMAC := mac.Sum(nil)
	return hmac.Equal(expectedHMAC, packet.Signature)
}

