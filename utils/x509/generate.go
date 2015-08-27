// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package x509

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// rsaGenerateKey allows for tests to patch out rsa key generation
var rsaGenerateKey = rsa.GenerateKey

// KeyBits is used to determine the number of bits to use for the RSA keys
// created using the GenerateKey function.
var KeyBits = 2048

type KeyPurposeId struct {
	OID asn1.ObjectIdentifier
}

type OtherName struct {
	A string `asn1:"utf8"`
}

type GeneralName struct {
	OID       asn1.ObjectIdentifier
	OtherName `asn1:"tag:0"`
}

type GeneralNames struct {
	GeneralName `asn1:"tag:0"`
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// GenerateKey makes a 2048 bit RSA no-passphrase SSH capable key.  The bit
// size is actually controlled by the KeyBits var. The private key returned is
// encoded to ASCII using the PKCS1 encoding.  The public key is suitable to
// be added into an authorized_keys file, and has the comment passed in as the
// comment part of the key.
func GenerateKey(subject pkix.Name, validFrom time.Time, validFor time.Duration) (private, public string, err error) {
	var priv interface{}

	priv, err = rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return "", "", fmt.Errorf("Failed to generate private key: %s", err)
	}

	notBefore := validFrom
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return "", "", fmt.Errorf("Failed to generate serial number: %s", err)
	}

	oidOtherName := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	commonName := OtherName{subject.CommonName}

	sequence := GeneralName{
		OID:       oidOtherName,
		OtherName: commonName,
	}

	val, err := asn1.Marshal(GeneralNames{sequence})

	if err != nil {
		return "", "", fmt.Errorf("Failed to marshal value: %s", err)
	}

	template := x509.Certificate{
		Subject:            subject,
		SerialNumber:       serialNumber,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.SHA1WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
				Critical: false,
				Value:    val,
			},
		},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return "", "", fmt.Errorf("Failed to create certificate: %s", err)
	}

	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	private_key := pem.EncodeToMemory(pemBlockForKey(priv))

	return string(private_key), string(certificate), nil
}
