package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
)

// MTLSServer represents an mTLS TCP proxy server
type MTLSServer struct {
	ListenPort int
	TargetPort int
	CACert     []byte
	ServerCert       []byte
	ServerKey        []byte
	AllowedSPIFFEIDs []string
}

// Start starts the mTLS TCP proxy
func (s *MTLSServer) Start() error {
	// Load CA
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(s.CACert) {
		return fmt.Errorf("failed to append CA certificate")
	}

	// Load Server Certificate
	cert, err := tls.X509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		return fmt.Errorf("failed to load server key pair: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	addr := fmt.Sprintf(":%d", s.ListenPort)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start mTLS listener: %w", err)
	}

	log.Printf("[mTLS Proxy] Listening on port %d, forwarding to %d", s.ListenPort, s.TargetPort)

	go func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				log.Printf("[mTLS Proxy] Accept error: %v", err)
				continue
			}

			go s.handleConnection(clientConn)
		}
	}()

	return nil
}

func (s *MTLSServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Ensure it's a TLS connection to check client cert
	tlsConn, ok := clientConn.(*tls.Conn)
	if ok {
		err := tlsConn.Handshake()
		if err != nil {
			log.Printf("[mTLS Proxy] TLS Handshake failed (NAT spoofing blocked): %v", err)
			return
		}
		
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			// Extract all SPIFFE IDs
			var clientSPIFFEIDs []string
			for _, uri := range cert.URIs {
				if uri.Scheme == "spiffe" {
					clientSPIFFEIDs = append(clientSPIFFEIDs, uri.String())
				}
			}
			log.Printf("[mTLS Proxy] Client authenticated: %s (SPIFFE IDs: %v)", cert.Subject.CommonName, clientSPIFFEIDs)

			// SPIFFE ID Enforcement
			if len(s.AllowedSPIFFEIDs) > 0 {
				allowed := false
				for _, allowedID := range s.AllowedSPIFFEIDs {
					for _, clientID := range clientSPIFFEIDs {
						if clientID == allowedID {
							allowed = true
							break
						}
					}
					if allowed {
						break
					}
				}
				if !allowed {
					log.Printf("[mTLS Proxy] Access Denied: Unauthorized SPIFFE IDs '%v'", clientSPIFFEIDs)
					return
				}
			}
		}
	}

	// Connect to target backend
	targetAddr := fmt.Sprintf("127.0.0.1:%d", s.TargetPort)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[mTLS Proxy] Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	log.Printf("[mTLS Proxy] Forwarding connection to %s", targetAddr)

	// Proxy data
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errc <- err
	}()

	<-errc
}
