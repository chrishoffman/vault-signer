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

	// key properties
	derived bool
	keyType keyType
}

type KeyConfig struct {
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
}

// NewVaultSigner creates a signer the leverages HashiCorp Vault's transit engine to sign
// using Go's built in crypto.Signer interface.
//
// Note that if namespaces are being used that they can be set on the Vault client, explicitly
// in the key config, or both where they will be combined.
func NewVaultSigner(vaultClient *api.Client, keyConfig *KeyConfig) (*VaultSigner, error) {
	if keyConfig.MountPath == "" {
		return nil, errors.New("key mount path is required")
	}
	if keyConfig.KeyName == "" {
		return nil, errors.New("key name is required")
	}

	signer := &VaultSigner{
		vaultClient: vaultClient,
		namespace:   keyConfig.Namespace,
		mountPath:   keyConfig.MountPath,
		keyName:     keyConfig.KeyName,
		context:     keyConfig.Context,
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

	return signer, nil
}

// Sign is part of the crypto.Signer interface and signs a given digest with the configured key
// in Vault's transit secrets engine
func (s *VaultSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	encodedDigest := base64.StdEncoding.EncodeToString(digest)

	var encodedContext string
	if s.derived {
		encodedContext = base64.StdEncoding.EncodeToString(s.context)
	}

	rsp, err := s.vaultClient.Logical().Write(s.buildKeyPath("sign"), map[string]interface{}{
		"context": encodedContext,
		"input":   encodedDigest,
	})
	if err != nil {
		return nil, err
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
		Derived            bool   `mapstructure:"derived"`
		SupportsSigning    bool   `mapstructure:"supports_signing"`
		SupportsDerivation bool   `mapstructure:"supports_derivation"`
		KeyType            string `mapstructure:"type"`
		Keys               map[int]struct {
			PublicKey string `mapstructure:"public_key"`
		} `mapstructure:"keys"`
		LatestVersion int `mapstructure:"latest_version"`
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

	publicKey, err := s.createPublicKey(keyInfo.Keys[keyInfo.LatestVersion].PublicKey)
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
