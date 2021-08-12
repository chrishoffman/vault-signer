package vaultsigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type keyType int

const (
	keyTypeRsa keyType = iota
	keyTypeEd25519
	keyTypeEcdsa
)

type VaultSigner struct {
	vaultClient *api.Client
	publicKey   crypto.PublicKey

	// key configuration
	namespace string
	mountPath string
	keyName   string
	context   []byte

	// key type specific configuration
	hashAlgorithm      HashAlgorithm
	signatureAlgorithm SignatureAlgorithm

	// key properties
	derived bool
	keyType keyType
}

type SignerConfig struct {
	// Namespace for the key. This can be provided in the key config, the vault client,
	// or both where they will be combined
	Namespace string

	// Mountpath is the mount path for transit secrets engine that holds the key
	MountPath string

	// Keyname is the name of the key in the transit secrets engine
	KeyName string

	// Context is the context for a derived key and can only be provided when working
	// with a derived key
	Context []byte

	// HashAlgorithm is the hash algorithm used in the signing operation. It is only supported
	// for RSA and ECDSA keys. If unset for supported keys, the value will default to sha2-256.
	HashAlgorithm HashAlgorithm

	// SignatureAlgorithm is the signature algorithm used in the signing operation. It is only
	// support for RSA keys. If unset for supported keys, the value will default to PKCS#1v15.
	SignatureAlgorithm SignatureAlgorithm
}

type HashAlgorithm string

const (
	HashAlgorithmSha1   HashAlgorithm = "sha1"
	HashAlgorithmSha224 HashAlgorithm = "sha2-224"
	HashAlgorithmSha256 HashAlgorithm = "sha2-256"
	HashAlgorithmSha384 HashAlgorithm = "sha2-384"
	HashAlgorithmSha512 HashAlgorithm = "sha2-512"
)

type SignatureAlgorithm string

const (
	SignatureAlgorithmRSAPSS      SignatureAlgorithm = "pss"
	SignatureAlgorithmRSAPKCS1v15 SignatureAlgorithm = "pkcs1v15"
)

// NewVaultSigner creates a signer the leverages HashiCorp Vault's transit engine to sign
// using Go's built in crypto.Signer interface.
func NewVaultSigner(vaultClient *api.Client, signerConfig *SignerConfig) (*VaultSigner, error) {
	if vaultClient == nil {
		return nil, errors.New("vault client is required")
	}
	if signerConfig.MountPath == "" {
		return nil, errors.New("key mount path is required")
	}
	if signerConfig.KeyName == "" {
		return nil, errors.New("key name is required")
	}

	signer := &VaultSigner{
		vaultClient:        vaultClient,
		namespace:          signerConfig.Namespace,
		mountPath:          signerConfig.MountPath,
		keyName:            signerConfig.KeyName,
		context:            signerConfig.Context,
		signatureAlgorithm: signerConfig.SignatureAlgorithm,
		hashAlgorithm:      signerConfig.HashAlgorithm,
	}
	if err := signer.retrieveKey(); err != nil {
		return nil, err
	}
	return signer, nil
}

// CloneWithContext copies the signer with a new context. This function will also retrieve
// the derived public key.
func (s *VaultSigner) CloneWithContext(context []byte) (*VaultSigner, error) {
	if !s.derived {
		return nil, errors.New("context can only be used with derived keys")
	}

	signer := &VaultSigner{
		vaultClient: s.vaultClient,
		namespace:   s.namespace,
		mountPath:   s.mountPath,
		keyName:     s.keyName,
		context:     context,
		derived:     s.derived,
		keyType:     s.keyType,
	}
	if err := signer.retrieveKey(); err != nil {
		return nil, err
	}

	if signer.keyType != keyTypeRsa && signer.keyType != keyTypeEcdsa && signer.hashAlgorithm != "" {
		return nil, errors.New("hash algorithm can only be set for RSA and ECDSA keys")
	}
	if signer.keyType != keyTypeRsa && signer.signatureAlgorithm != "" {
		return nil, errors.New("signature algorithm can only be set for RSA keys")
	}

	return signer, nil
}

// Sign is part of the crypto.Signer interface and signs a given digest with the configured key
// in Vault's transit secrets engine
func (s *VaultSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	requestData := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(digest),
	}

	if s.derived {
		requestData["context"] = base64.StdEncoding.EncodeToString(s.context)
	}

	switch s.keyType {
	case keyTypeRsa:
		requestData["signature_algorithm"] = s.signatureAlgorithm
		if s.signatureAlgorithm == "" {
			requestData["signature_algorithm"] = SignatureAlgorithmRSAPKCS1v15
		}
		fallthrough
	case keyTypeEcdsa:
		if s.hashAlgorithm != "" {
			requestData["hash_algorithm"] = s.hashAlgorithm
		}
	}

	rsp, err := s.vaultClient.Logical().Write(s.buildKeyPath("sign"), requestData)
	if err != nil {
		return nil, err
	}
	if rsp == nil {
		return nil, errors.New("no secret returned")
	}

	sig, ok := rsp.Data["signature"]
	if !ok {
		return nil, errors.New("no signature returned")
	}
	splitSig := strings.Split(sig.(string), ":")
	if len(splitSig) != 3 {
		return nil, errors.New("malformed signature value")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(splitSig[2])
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %s", err)
	}

	return sigBytes, nil
}

// Public returns the public key for the key stored in transit's secrets engine
func (s *VaultSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *VaultSigner) retrieveKey() error {
	keyPath := s.buildKeyPath("keys")

	// context is ignored if the key is not derived so it is always sent
	var context string
	if len(s.context) > 0 {
		context = base64.StdEncoding.EncodeToString(s.context)
	}
	rsp, err := s.vaultClient.Logical().ReadWithData(keyPath, map[string][]string{
		"context": {
			context,
		},
	})
	if err != nil {
		return err
	}

	keyInfo := struct {
		Derived            bool        `mapstructure:"derived"`
		SupportsSigning    bool        `mapstructure:"supports_signing"`
		SupportsDerivation bool        `mapstructure:"supports_derivation"`
		KeyType            string      `mapstructure:"type"`
		Keys               interface{} `mapstructure:"keys"`
		LatestVersion      int         `mapstructure:"latest_version"`
	}{}
	if err := mapstructure.WeakDecode(rsp.Data, &keyInfo); err != nil {
		return err
	}

	if !keyInfo.SupportsSigning {
		return errors.New("key does not support signing")
	}
	if keyInfo.Derived && len(s.context) == 0 {
		return errors.New("context must be provided for derived keys")
	}
	if !keyInfo.SupportsDerivation && len(s.context) > 0 {
		return errors.New("context provided by derivation is not supported")
	}

	s.derived = keyInfo.Derived

	switch keyInfo.KeyType {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		s.keyType = keyTypeRsa
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		s.keyType = keyTypeEcdsa
	case "ed25519":
		s.keyType = keyTypeEd25519
	default:
		return errors.New("unsupported key type")
	}

	publicKeyInfo := map[int]struct {
		PublicKey string `mapstructure:"public_key"`
	}{}
	if err := mapstructure.WeakDecode(keyInfo.Keys, &publicKeyInfo); err != nil {
		return err
	}

	publicKey, err := s.createPublicKey(publicKeyInfo[keyInfo.LatestVersion].PublicKey)
	if err != nil {
		return err
	}
	s.publicKey = publicKey

	return nil
}

func (s *VaultSigner) buildKeyPath(operation string) string {
	return path.Join(s.namespace, s.mountPath, operation, s.keyName)
}

func (s *VaultSigner) createPublicKey(keyData string) (crypto.PublicKey, error) {
	switch s.keyType {
	case keyTypeRsa:
		block, _ := pem.Decode([]byte(keyData))
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to RSA public key")
		}
		return key, nil
	case keyTypeEcdsa:
		block, _ := pem.Decode([]byte(keyData))
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to ECDSA public key")
		}
		return key, nil
	case keyTypeEd25519:
		key, err := base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			return nil, err
		}

		return ed25519.PublicKey(key), nil
	}
	return nil, errors.New("unknown public key type")
}
