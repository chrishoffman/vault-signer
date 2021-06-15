package vaultsigner_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"
	"path"
	"testing"

	signer "github.com/chrishoffman/vault-signer"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
)

var _ crypto.Signer = (*signer.VaultSigner)(nil)

func TestNew_ValidateConstructor(t *testing.T) {
	_, err := signer.NewVaultSigner(nil, nil)
	if err == nil {
		t.Fatal("error expected")
	}

	vaultConfig := api.DefaultConfig()
	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("error creating vault client")
	}

	signerConfig := &signer.SignerConfig{
		KeyName: "test",
	}
	_, err = signer.NewVaultSigner(vaultClient, signerConfig)
	if err == nil {
		t.Fatalf("error expected")
	}

	signerConfig = &signer.SignerConfig{
		MountPath: "test",
	}
	_, err = signer.NewVaultSigner(vaultClient, signerConfig)
	if err == nil {
		t.Fatalf("error expected")
	}
}

func Test_DockerTests(t *testing.T) {
	cleanup, client := prepareTestContainer(t)
	defer cleanup()

	t.Run("sign", func(t *testing.T) {
		var tests = []struct {
			keyType      string
			derived      bool
			signerConfig *signer.SignerConfig
		}{
			{"rsa-2048", false, nil},
			{"rsa-2048", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha1}},
			{"rsa-2048", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha224}},
			{"rsa-2048", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha256}},
			{"rsa-2048", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha384}},
			{"rsa-2048", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha512}},
			{"rsa-2048", false, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS}},
			{"rsa-2048", false, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS, HashAlgorithm: signer.HashAlgorithmSha1}},
			{"rsa-2048", false, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS, HashAlgorithm: signer.HashAlgorithmSha224}},
			{"rsa-2048", false, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS, HashAlgorithm: signer.HashAlgorithmSha256}},
			{"rsa-2048", false, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS, HashAlgorithm: signer.HashAlgorithmSha384}},
			{"rsa-2048", false, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS, HashAlgorithm: signer.HashAlgorithmSha512}},
			{"rsa-3072", false, nil},
			{"rsa-4096", false, nil},
			{"ecdsa-p256", false, nil},
			{"ecdsa-p256", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha1}},
			{"ecdsa-p256", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha224}},
			{"ecdsa-p256", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha256}},
			{"ecdsa-p256", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha384}},
			{"ecdsa-p256", false, &signer.SignerConfig{HashAlgorithm: signer.HashAlgorithmSha512}},
			{"ecdsa-p384", false, nil},
			{"ecdsa-p521", false, nil},
			{"ed25519", false, nil},
			{"ed25519", true, nil},
		}

		for _, tt := range tests {
			testName := fmt.Sprintf("%s,derived:%t", tt.keyType, tt.derived)
			t.Run(testName, func(t *testing.T) {
				signer, err := testSigner(t, client, tt.keyType, tt.derived, tt.signerConfig)
				if err != nil {
					t.Fatalf("error creating signer: %v", err)
				}
				testSign(t, signer, tt.keyType, tt.signerConfig)
			})
		}
	})

	t.Run("clone with context, not derived", func(t *testing.T) {
		signer, err := testSigner(t, client, "rsa-2048", false, nil)
		if err != nil {
			t.Fatalf("error creating signer: %v", err)
		}
		_, err = signer.CloneWithContext([]byte("abc"))
		if err == nil {
			t.Fatalf("should not be able to clone non-derived signer")
		}
	})

	t.Run("clone with context, derived", func(t *testing.T) {
		signer, err := testSigner(t, client, "ed25519", true, nil)
		if err != nil {
			t.Fatalf("error creating signer: %v", err)
		}

		clonedSigner, err := signer.CloneWithContext([]byte("abc"))
		if err != nil {
			t.Fatalf("should not be able to clone non-derived signer")
		}
		testSign(t, clonedSigner, "ed25519", nil)
	})

	t.Run("key does not support signing", func(t *testing.T) {
		_, err := testSigner(t, client, "aes256-gcm96", true, nil)
		if err == nil {
			t.Fatalf("creating signer that does not support signing should have errored")
		}
	})

	t.Run("namespace support", func(t *testing.T) {
		namespacePath := newUUID(t)
		if _, err := client.Logical().Write(path.Join("sys/namespaces", namespacePath), map[string]interface{}{}); err != nil {
			t.Fatalf("error creating namespace: %s", err)
		}

		client.SetNamespace(namespacePath)
		signer, err := testSigner(t, client, "ed25519", false, nil)
		if err != nil {
			t.Fatalf("error creating signer: %v", err)
		}
		testSign(t, signer, "ed25519", nil)

		// reset namespace
		client.SetNamespace("")
	})
}

func testSign(t *testing.T, vsigner *signer.VaultSigner, keyType string, signerConfig *signer.SignerConfig) {
	if signerConfig == nil {
		signerConfig = &signer.SignerConfig{}
	}

	publicKey := vsigner.Public()
	if publicKey == nil {
		t.Fatalf("invalid public key")
	}

	testDigest := []byte(newUUID(t))
	signature, err := vsigner.Sign(nil, testDigest, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if len(signature) == 0 {
		t.Fatalf("invalid signature")
	}

	switch keyType {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		algo, hash := hashValue(signerConfig.HashAlgorithm, testDigest)
		rsaPublicKey := publicKey.(*rsa.PublicKey)

		switch signerConfig.SignatureAlgorithm {
		case signer.SignatureAlgorithmRSAPSS:
			if err := rsa.VerifyPSS(rsaPublicKey, algo, hash, signature, nil); err != nil {
				t.Fatalf("signature does not verify")
			}
		default:
			if err := rsa.VerifyPKCS1v15(rsaPublicKey, algo, hash, signature); err != nil {
				t.Fatalf("signature does not verify")
			}
		}
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		_, hash := hashValue(signerConfig.HashAlgorithm, testDigest)
		sig := struct {
			R, S *big.Int
		}{}
		_, err = asn1.Unmarshal(signature, &sig)
		if err != nil {
			t.Fatalf("unable to unmarshal signature")
		}
		ecdsaPublicKey := publicKey.(*ecdsa.PublicKey)
		if ok := ecdsa.Verify(ecdsaPublicKey, hash, sig.R, sig.S); !ok {
			t.Fatalf("signature does not verify")
		}
	case "ed25519":
		ed25519PublicKey := publicKey.(ed25519.PublicKey)
		if ok := ed25519.Verify(ed25519PublicKey, testDigest, signature); !ok {
			t.Fatalf("signature does not verify")
		}
	default:
		t.Fatalf("no verification function")
	}
}

func hashValue(algo signer.HashAlgorithm, data []byte) (crypto.Hash, []byte) {
	switch algo {
	case signer.HashAlgorithmSha1:
		sum := sha1.Sum(data)
		return crypto.SHA1, sum[:]
	case signer.HashAlgorithmSha224:
		sum := sha256.Sum224(data)
		return crypto.SHA224, sum[:]
	case signer.HashAlgorithmSha384:
		sum := sha512.Sum384(data)
		return crypto.SHA384, sum[:]
	case signer.HashAlgorithmSha512:
		sum := sha512.Sum512(data)
		return crypto.SHA512, sum[:]
	default: // signer.HashAlgorithmSha256:
		sum := sha256.Sum256(data)
		return crypto.SHA256, sum[:]
	}
}

func testSigner(t *testing.T, client *api.Client, keyType string, derived bool, signerConfig *signer.SignerConfig) (*signer.VaultSigner, error) {
	mountPath, keyName := createTransitMount(t, client, keyType, derived)
	config := signerConfig
	if signerConfig == nil {
		config = &signer.SignerConfig{}
	}
	config.MountPath = mountPath
	config.KeyName = keyName

	if derived {
		config.Context = []byte(newUUID(t))
	}
	return signer.NewVaultSigner(client, config)
}

func createTransitMount(t *testing.T, client *api.Client, keyType string, derived bool) (string, string) {
	mountPath := newUUID(t)
	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Fatalf("Error creating vault mount: %s", err)
	}

	// Create derived signing key
	keyName := newUUID(t)
	keyOptions := map[string]interface{}{
		"derived": derived,
		"type":    keyType,
	}
	_, err := client.Logical().Write(path.Join(mountPath, "keys", keyName), keyOptions)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	return mountPath, keyName
}

func newUUID(t *testing.T) string {
	generatedUUID, err := uuid.NewUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return generatedUUID.String()
}

func prepareTestContainer(t *testing.T) (func(), *api.Client) {
	testUUID, err := uuid.NewUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testToken := testUUID.String()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "hashicorp/vault-enterprise",
		Tag:        "latest",
		Cmd: []string{"server", "-log-level=trace", "-dev", fmt.Sprintf("-dev-root-token-id=%s", testToken),
			"-dev-listen-address=0.0.0.0:8200"},
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		t.Fatalf("Could not start local Vault docker container: %s", err)
	}

	cleanup := func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = fmt.Sprintf("http://127.0.0.1:%s", resource.GetPort("8200/tcp"))
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Failed to set up API client: %s", err)
	}
	client.SetToken(testToken)

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		// Unmount default kv mount to ensure availability
		if err := client.Sys().Unmount("kv"); err != nil {
			return err
		}

		return nil
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to vault: %s", err)
	}
	return cleanup, client
}
