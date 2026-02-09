# vault-signer [![test](https://github.com/chrishoffman/vault-signer/workflows/test/badge.svg)](https://github.com/chrishoffman/vault-signer/actions/workflows/test.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/chrishoffman/vault-signer.svg)](https://pkg.go.dev/github.com/chrishoffman/vault-signer)

A Go `crypto.Signer` implementation that leverages HashiCorp Vault's transit secrets engine for cryptographic operations.

## Why vault-signer?

Keep your private keys secure in Vault while seamlessly integrating with Go's standard crypto interfaces. Perfect for:

- **Signing JWTs** without exposing private keys to your application
- **Creating x509 certificates** with Vault-managed keys
- **Centralizing key management** across your infrastructure
- **Meeting compliance requirements** that mandate hardware security modules (HSMs)

With vault-signer, your signing operations use Vault's transit engine while your code uses familiar Go crypto patterns.

## Features

- Implements Go's standard `crypto.Signer` interface
- Supports multiple signature algorithms (RSA, ECDSA, Ed25519)
- Drop-in replacement for local private keys
- Works with popular libraries like go-jose and x509
- Production-ready with comprehensive test coverage

## Installation

```bash
go get github.com/chrishoffman/vault-signer
```

## Usage
To use `vault-signer` just pass in a Vault API client and key configuration to get a struct that implements the Go [crypto.Signer](https://golang.org/pkg/crypto/#Signer) interface.

```go
vaultConfig := api.DefaultConfig()
vaultClient, err := api.NewClient(vaultConfig)
if err != nil {
	log.Fatalf("err: %s", err)
}

signerConfig := &vaultsigner.SignerConfig{
	MountPath: "transit",
	KeyName:   "test-key",
}
vaultSigner, err := vaultsigner.NewVaultSigner(vaultClient, signerConfig)
if err != nil {
	log.Fatalf("err: %s", err)
}
```

## Examples

### Sign JWT

```go
import (
	"log"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
)

// using VaultSigner setup above

opaqueSigner := cryptosigner.Opaque(vaultSigner)
signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: opaqueSigner}
signer, err := jose.NewSigner(signingKey, nil)
if err != nil {
	log.Fatalf("error creating signer: %v", err)
}

builder := jwt.Signed(signer)
pubClaims := jwt.Claims{
	Issuer:   "issuer1",
	Subject:  "subject1",
	ID:       "id1",
	Audience: jwt.Audience{"aud1", "aud2"},
	IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
	Expiry:   jwt.NewNumericDate(time.Date(2030, 1, 1, 0, 15, 0, 0, time.UTC)),
}
builder = builder.Claims(pubClaims)

rawJWT, err := builder.Serialize()
if err != nil {
	log.Fatalf("failed to create JWT: %+v", err)
}

// decode the raw JWT
parsedJWT, err := jwt.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.EdDSA})
if err != nil {
	log.Fatalf("failed to parse JWT:%+v", err)
}

// verify signature
resultCl := map[string]interface{}{}
if err := parsedJWT.Claims(vaultSigner.Public(), &resultCl); err != nil {
	log.Fatalf("Failed to verify JWT: %+v", err)
}
```

### Sign x509 Certificate

```go
import (
	"crypto/rand"
	"crypto/x509"
	"log"
)

// using VaultSigner setup above

template := &x509.Certificate{
	Subject: pkix.Name{
		CommonName: "Test",
	},
	SerialNumber:       big.NewInt(1),
	NotAfter:           time.Now().Add(time.Hour).UTC(),
	SignatureAlgorithm: x509.SHA256WithRSA,
}

cert, err = x509.CreateCertificate(rand.Reader, template, template, vaultSigner.Public(), vaultSigner)
if err != nil {
	log.Fatalf("Error creating certificate: %s", err)
}
```
