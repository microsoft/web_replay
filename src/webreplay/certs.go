// Modifications Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.
//
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package webreplay

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Returns a TLS configuration that serves a recorded server leaf cert signed by
// root CA.
func ReplayTLSConfig(leafs []tls.Certificate, tls_int tls.Certificate, ma *MultipleArchive) (*tls.Config, error) {
	leaf_certs, err := GetLeafCerts(leafs)

	if err != nil {
		return nil, fmt.Errorf("bad local certs: %v", err)
	}

	tls_int_cert, err := GetIntCert(tls_int)

	if err != nil {
		return nil, fmt.Errorf("bad local cert: %v", err)
	}

	tp := &tlsProxy{leafs, leaf_certs, &tls_int, tls_int_cert, ma, nil, sync.Mutex{}, make(map[string][]byte)}

	return &tls.Config{
		GetConfigForClient: tp.getReplayConfigForClient,
	}, nil
}

// Returns a TLS configuration that serves a server leaf cert fetched over the
// network on demand.
func RecordTLSConfig(leafs []tls.Certificate, tls_int tls.Certificate, mwa *MultipleWritableArchive) (*tls.Config, error) {
	leaf_certs, err := GetLeafCerts(leafs)

	if err != nil {
		return nil, fmt.Errorf("bad local certs: %v", err)
	}

	tls_int_cert, err := GetIntCert(tls_int)

	if err != nil {
		return nil, fmt.Errorf("bad local cert: %v", err)
	}

	tp := &tlsProxy{leafs, leaf_certs, &tls_int, tls_int_cert, nil, mwa, sync.Mutex{}, nil}

	return &tls.Config{
		GetConfigForClient: tp.getRecordConfigForClient,
	}, nil
}

func GetLeafCerts(leafs []tls.Certificate) ([]*x509.Certificate, error) {
	leaf_certs := []*x509.Certificate{}

	for _, leaf := range leafs {
		leaf_cert, err := x509.ParseCertificate(leaf.Certificate[0])

		if err != nil {
			return nil, err
		}

		leaf_cert.IsCA = false
		leaf_cert.BasicConstraintsValid = true

		leaf_certs = append(leaf_certs, leaf_cert)
	}

	return leaf_certs, nil
}

func GetIntCert(tls_int tls.Certificate) (*x509.Certificate, error) {
	tls_int_cert, err := x509.ParseCertificate(tls_int.Certificate[0])

	if err != nil {
		return nil, err
	}

	tls_int_cert.IsCA = true
	tls_int_cert.BasicConstraintsValid = true

	return tls_int_cert, nil
}

// Mints a dummy server cert when the real one is not recorded.
func MintDummyCertificate(serverName string, leafCert *x509.Certificate, intCert *x509.Certificate, intKey crypto.PrivateKey) ([]byte, string, error) {
	template := leafCert

	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}

	var buf [20]byte

	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, "", fmt.Errorf("create cert failed: %v", err)
	}

	template.SerialNumber.SetBytes(buf[:])

	dt := time.Now()

	template.NotBefore = dt.Add(-24 * time.Hour)

	// Certs cannot be valid for longer than 12 mths.
	template.NotAfter = dt.Add(12 * 30 * 24 * time.Hour)

	template.SignatureAlgorithm = intCert.SignatureAlgorithm
	template.Issuer = template.Subject

	derBytes, err := x509.CreateCertificate(rand.Reader, template, intCert, template.PublicKey, intKey)

	if err != nil {
		return nil, "", fmt.Errorf("create cert failed: %v", err)
	}

	return derBytes, "", err
}

// Returns DER encoded server cert.
func MintServerCert(serverName string, leafCert *x509.Certificate, intCert *x509.Certificate, intKey crypto.PrivateKey) ([]byte, string, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", serverName), &tls.Config{
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})

	if err != nil {
		return nil, "", fmt.Errorf("Couldn't reach host %s: %v", serverName, err)
	}

	defer conn.Close()

	conn.Handshake()

	template := conn.ConnectionState().PeerCertificates[0]

	dt := time.Now()

	template.Subject.CommonName = serverName
	template.NotBefore = dt.Add(-24 * time.Hour)

	// Certs cannot be valid for longer than 12 mths.
	template.NotAfter = dt.Add(12 * 30 * 24 * time.Hour)
	template.SignatureAlgorithm = intCert.SignatureAlgorithm

	var buf [20]byte

	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, "", err
	}

	template.SerialNumber.SetBytes(buf[:])

	template.Issuer = intCert.Subject
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	negotiatedProtocol := conn.ConnectionState().NegotiatedProtocol

	if err != nil {
		return nil, "", err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, intCert, leafCert.PublicKey, intKey)

	return derBytes, negotiatedProtocol, err
}

type tlsProxy struct {
	leafs      []tls.Certificate
	leaf_certs []*x509.Certificate

	tls_int      *tls.Certificate
	tls_int_cert *x509.Certificate

	ma  *MultipleArchive
	mwa *MultipleWritableArchive

	mu              sync.Mutex
	dummy_certs_map map[string][]byte
}

// TODO: For now, this just returns a self-signed cert using the given ServerName.
// In the future, for better HTTP/2 support, we may want to record host equivalence
// classes in the archive, where an equivalence class contains all hosts that can be
// served by the same IP. We can then run a DNS proxy that maps all hostnames in the
// same equivalence class to the same local port, which models the possibility that
// every equivalence class of hostnames can be served over the same HTTP/2 connection.
func (tp *tlsProxy) getReplayConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	h := clientHello.ServerName

	if h == "" {
		return nil, fmt.Errorf("SNI not used")
	}

	derBytes, negotiatedProtocol, err := tp.ma.FindHostTlsConfig(h)

	tp.mu.Lock()
	defer tp.mu.Unlock()

	if err != nil || derBytes == nil {
		if _, ok := tp.dummy_certs_map[h]; !ok {
			for i := 0; i < len(tp.leaf_certs); i++ {
				derBytes, negotiatedProtocol, err = MintDummyCertificate(h, tp.leaf_certs[i], tp.tls_int_cert, tp.tls_int.PrivateKey)

				if err != nil {
					return nil, err
				}

				tp.dummy_certs_map[h] = append(tp.dummy_certs_map[h], derBytes...)
			}
		}

		derBytes = tp.dummy_certs_map[h]
	}

	certBytes := ParseDerBytes(derBytes)

	certificates := []tls.Certificate{}

	for i := 0; i < len(certBytes); i++ {
		certificates = append(certificates, tls.Certificate{
			Certificate: [][]byte{certBytes[i]},
			PrivateKey:  tp.leafs[i].PrivateKey,
		})
	}

	return &tls.Config{
		Certificates: certificates,
		NextProtos:   buildNextProtos(negotiatedProtocol),
	}, nil
}

func buildNextProtos(negotiatedProtocol string) []string {
	if negotiatedProtocol == "h2" {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

// Extract ASN.1 DER encoded certificates from byte array.
// ASN.1 DER encoding is a tag, length, value encoding system for each element.
// Depending on the length of the certificate, there are three possible sequence starts:
//  1. 0x30, one byte of length field
//  2. 0x30, 0x81, one byte of length field
//  3. 0x30, 0x82, two bytes of length field
func ParseDerBytes(derBytes []byte) [][]byte {
	var certBytes [][]byte

	for i := 0; i < len(derBytes); {
		certEndIndex := 0

		switch derBytes[i+1] {
		case 0x81:
			certEndIndex = i + 3 + int(derBytes[i+2])
		case 0x82:
			certEndIndex = i + 4 + int(derBytes[i+2])*256 + int(derBytes[i+3])
		default:
			certEndIndex = i + 2 + int(derBytes[i+1])
		}

		certBytes = append(certBytes, derBytes[i:certEndIndex])
		i = certEndIndex
	}

	return certBytes
}

func (tp *tlsProxy) getRecordConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	h := clientHello.ServerName

	if h == "" {
		return nil, fmt.Errorf("SNI not used")
	}

	certificates := []tls.Certificate{}
	derBytes, negotiatedProtocol, err := tp.mwa.CurrentArchive().FindHostTlsConfig(h)

	if err == nil && derBytes != nil {
		certBytes := ParseDerBytes(derBytes)

		for i := 0; i < len(certBytes); i++ {
			certificates = append(certificates, tls.Certificate{
				Certificate: [][]byte{certBytes[i]},
				PrivateKey:  tp.leafs[i].PrivateKey,
			})
		}

		return &tls.Config{
			Certificates: certificates,
			NextProtos:   buildNextProtos(negotiatedProtocol),
		}, nil
	}

	totalDerBytes := []byte{}

	for i := 0; i < len(tp.leafs); i++ {
		derBytes, negotiatedProtocol, err = MintServerCert(h, tp.leaf_certs[i], tp.tls_int_cert, tp.tls_int.PrivateKey)

		if err != nil {
			return nil, fmt.Errorf("create cert failed: %v", err)
		}

		certificates = append(certificates, tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  tp.leafs[i].PrivateKey})

		totalDerBytes = append(totalDerBytes, derBytes...)
	}

	tp.mwa.CurrentArchive().RecordTlsConfig(h, totalDerBytes, negotiatedProtocol)

	return &tls.Config{
		Certificates: certificates,
		NextProtos:   buildNextProtos(negotiatedProtocol),
	}, nil
}
