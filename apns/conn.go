package apns

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
)

type Conn struct {
	c *tls.Conn
}

func (c *Conn) Close() error {
	return c.c.Close()
}

// StartConnection establishes a connection with a random APNS courier.
// The caller must remember to close the connection when they are done with it.
func StartConnection(key *rsa.PrivateKey, certBlock *pem.Block) (*Conn, error) {
	courier, err := getRandomCourierHost()
	if err != nil {
		return nil, err
	}

	caCert, err := tls.X509KeyPair(certBlock.Bytes, x509.MarshalPKCS1PrivateKey(key))

	conn, err := tls.Dial("tcp", courier, &tls.Config{Certificates: []tls.Certificate{caCert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13})
	if err != nil {
		return nil, err
	}

	return &Conn{conn}, nil
}

func getRandomCourierHost() (string, error) {
	return "windows.courier.push.apple.com:5223", nil
}
