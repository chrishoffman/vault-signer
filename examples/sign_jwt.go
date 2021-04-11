package examples

import (
	"log"
	"time"

	vaultsigner "github.com/chrishoffman/vault-signer"
	"github.com/hashicorp/vault/api"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

func SignJWT() {
	vaultConfig := api.DefaultConfig()
	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	// key exists on Vault instance at transit/keys/test-key
	// key config:
	//  type: ed25519
	//  derived: false
	signerConfig := &vaultsigner.SignerConfig{
		MountPath: "transit",
		KeyName:   "test-key",
	}
	vaultSigner, err := vaultsigner.NewVaultSigner(vaultClient, signerConfig)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	// Set up JWT signer
	opaqueSigner := cryptosigner.Opaque(vaultSigner)
	signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: opaqueSigner}
	signer, err := jose.NewSigner(signingKey, nil)

	// Build JWT
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
	log.Printf("JWT: %s\n", rawJWT)
}

func SignJWTWithDerivedKey() {
	vaultConfig := api.DefaultConfig()
	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	// key exists on Vault instance at transit/keys/test-key
	// key config:
	//  type: ed25519
	//  derived: true
	signerConfig := &vaultsigner.SignerConfig{
		MountPath: "transit",
		KeyName:   "test-key",
		Context:   []byte("context-value"),
	}
	vaultSigner, err := vaultsigner.NewVaultSigner(vaultClient, signerConfig)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	// Set up JWT signer
	opaqueSigner := cryptosigner.Opaque(vaultSigner)
	signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: opaqueSigner}
	signer, err := jose.NewSigner(signingKey, nil)

	// Build JWT
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
	log.Printf("JWT: %s\n", rawJWT)
}
