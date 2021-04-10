package vaultsigner

import (
	"crypto"
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
	keyTypeRsa2048 keyType = iota
	//	keyTypeRsa3072
	//	keyTypeRsa4096
	keyTypeEd25519
	//	keyTypeEcdsaP256
	//	keyTypeEcdsaP384
	//	keyTypeEcdsaP521
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
	Context string
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

	keyInfo, err := s.retrieveKeyInfo(context)
	if err != nil {
		return nil, err
	}
	publicKey, err := s.createPublicKey(keyInfo.keys[keyInfo.latestVersion].publicKey)
	if err != nil {
		return nil, err
	}

	return &VaultSigner{
		vaultClient: s.vaultClient,
		publicKey:   publicKey,
		namespace:   s.namespace,
		mountPath:   s.mountPath,
		keyName:     s.keyName,
		context:     context,
		derived:     s.derived,
		keyType:     s.keyType,
	}, nil
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
	keyInfo, err := s.retrieveKeyInfo(nil)
	if err != nil {
		return err
	}

	if !keyInfo.supportsSigning {
		return errors.New("key does not support signing")
	}
	if keyInfo.derived && len(s.context) == 0 {
		return errors.New("context must be provided for derived keys")
	}
	if !keyInfo.supportsDerivation && len(s.context) > 0 {
		return errors.New("context provided by derivation is not supported")
	}

	s.derived = keyInfo.derived

	switch keyInfo.keyType {
	case "rsa-2048":
		s.keyType = keyTypeRsa2048
	case "ed25519":
		s.keyType = keyTypeEd25519
	default:
		return errors.New("unsupported key type")
	}

	var encodedPublicKey string
	if s.derived {
		// validation complete, retrieve public key with context
		contextKeyInfo, err := s.retrieveKeyInfo(s.context)
		if err != nil {
			return err
		}
		encodedPublicKey = contextKeyInfo.keys[contextKeyInfo.latestVersion].publicKey
	} else {
		encodedPublicKey = keyInfo.keys[keyInfo.latestVersion].publicKey
	}
	publicKey, err := s.createPublicKey(encodedPublicKey)
	if err != nil {
		return err
	}
	s.publicKey = publicKey

	return nil
}

type keyInfo struct {
	derived            bool   `mapstructure:"derived"`
	supportsSigning    bool   `mapstructure:"supports_signing"`
	supportsDerivation bool   `mapstructure:"supports_derivation"`
	keyType            string `mapstructure:"type"`
	keys               map[int]struct {
		publicKey string `mapstructure:"public_key"`
	} `mapstructure:"keys"`
	latestVersion int `mapstructure:"latest_version"`
}

func (s *VaultSigner) retrieveKeyInfo(context []byte) (*keyInfo, error) {
	keyPath := s.buildKeyPath("keys")

	var rsp *api.Secret
	var err error

	if len(context) == 0 {
		rsp, err = s.vaultClient.Logical().Read(keyPath)
		if err != nil {
			return nil, err
		}
	} else {
		encodedContext := base64.StdEncoding.EncodeToString(context)
		rsp, err = s.vaultClient.Logical().ReadWithData(keyPath, map[string][]string{
			"context": {
				encodedContext,
			},
		})
		if err != nil {
			return nil, err
		}
	}

	keyInfo := new(keyInfo)
	if err := mapstructure.WeakDecode(rsp.Data, keyInfo); err != nil {
		return nil, err
	}

	return keyInfo, nil
}

func (s *VaultSigner) buildKeyPath(operation string) string {
	return path.Join(s.namespace, s.mountPath, operation, s.keyName)
}

func (s *VaultSigner) createPublicKey(keyData string) (crypto.PublicKey, error) {
	switch s.keyType {
	case keyTypeRsa2048:
		block, _ := pem.Decode([]byte(keyData))
		ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := ifc.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to RSA public key")
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
