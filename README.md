# vault-signer [![test](https://github.com/chrishoffman/vault-signer/workflows/test/badge.svg?branch=main)](https://github.com/chrishoffman/vault-signer/actions/workflows/test.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/chrishoffman/vault-signer.svg)](https://pkg.go.dev/github.com/chrishoffman/vault-signer)
A Go crypto.Signer that leverages the transit secrets engine in HashiCorp Vault

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

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
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

rawJWT, err := builder.CompactSerialize()
if err != nil {
	log.Fatalf("failed to create JWT: %+v", err)
}

// decode the raw JWT
parsedJWT, err := jwt.ParseSigned(rawJWT)
if err != nil {
	log.Fatalf("failed to parse JWT:%+v", err)
}

// verify signature
resultCl := map[string]interface{}{}
if err := parsedJWT.Claims(vaultSigner.Public(), &resultCl); err != nil {
	log.Fatalf("Failed to verify JWT: %+v", err)
}
```
