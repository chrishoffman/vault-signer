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
	"io/ioutil"
	"math/big"
	"os"
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

	keyConfig := &signer.KeyConfig{
		KeyName: "test",
	}
	_, err = signer.NewVaultSigner(vaultClient, keyConfig)
	if err == nil {
		t.Fatalf("error expected")
	}

	keyConfig = &signer.KeyConfig{
		MountPath: "test",
	}
	_, err = signer.NewVaultSigner(vaultClient, keyConfig)
	if err == nil {
		t.Fatalf("error expected")
	}
}

func Test_DockerTests(t *testing.T) {
	cleanup, client := prepareTestContainer(t)
	defer cleanup()

	var tests = []struct {
		keyType   string
		derived   bool
		keyConfig *signer.KeyConfig
	}{
		{"rsa-2048", false, nil},
		{"rsa-2048", false, &signer.KeyConfig{SignatureAlgorithm: signer.SignatureAlgorithmPKCS1v15}},
		{"rsa-2048", false, &signer.KeyConfig{SignatureAlgorithm: signer.SignatureAlgorithmPKCS1v15, HashAlgorithm: signer.HashAlgorithmSha1}},
		{"rsa-2048", false, &signer.KeyConfig{SignatureAlgorithm: signer.SignatureAlgorithmPKCS1v15, HashAlgorithm: signer.HashAlgorithmSha224}},
		{"rsa-2048", false, &signer.KeyConfig{SignatureAlgorithm: signer.SignatureAlgorithmPKCS1v15, HashAlgorithm: signer.HashAlgorithmSha256}},
		{"rsa-2048", false, &signer.KeyConfig{SignatureAlgorithm: signer.SignatureAlgorithmPKCS1v15, HashAlgorithm: signer.HashAlgorithmSha384}},
		{"rsa-2048", false, &signer.KeyConfig{SignatureAlgorithm: signer.SignatureAlgorithmPKCS1v15, HashAlgorithm: signer.HashAlgorithmSha512}},
		{"rsa-2048", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha1}},
		{"rsa-2048", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha224}},
		{"rsa-2048", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha256}},
		{"rsa-2048", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha384}},
		{"rsa-2048", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha512}},
		{"rsa-3072", false, nil},
		{"rsa-4096", false, nil},
		{"ecdsa-p256", false, nil},
		{"ecdsa-p256", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha1}},
		{"ecdsa-p256", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha224}},
		{"ecdsa-p256", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha256}},
		{"ecdsa-p256", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha384}},
		{"ecdsa-p256", false, &signer.KeyConfig{HashAlgorithm: signer.HashAlgorithmSha512}},
		{"ecdsa-p384", false, nil},
		{"ecdsa-p521", false, nil},
		{"ed25519", false, nil},
		{"ed25519", true, nil},
	}

	t.Run("sign", func(t *testing.T) {
		for _, tt := range tests {
			testName := fmt.Sprintf("%s,derived:%t", tt.keyType, tt.derived)
			t.Run(testName, func(t *testing.T) {
				signer, err := testSigner(t, client, tt.keyType, tt.derived, tt.keyConfig)
				if err != nil {
					t.Fatalf("error creating signer: %v", err)
				}
				testSign(t, signer, tt.keyType, tt.keyConfig)
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
}

func testSign(t *testing.T, vsigner *signer.VaultSigner, keyType string, keyConfig *signer.KeyConfig) {
	if keyConfig == nil {
		keyConfig = &signer.KeyConfig{}
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
		algo, hash := hashValue(keyConfig.HashAlgorithm, testDigest)
		rsaPublicKey := publicKey.(*rsa.PublicKey)

		switch keyConfig.SignatureAlgorithm {
		case signer.SignatureAlgorithmPKCS1v15:
			if err := rsa.VerifyPKCS1v15(rsaPublicKey, algo, hash, signature); err != nil {
				t.Fatalf("signature does not verify")
			}
		default:
			if err := rsa.VerifyPSS(rsaPublicKey, algo, hash, signature, nil); err != nil {
				t.Fatalf("signature does not verify")
			}
		}
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		_, hash := hashValue(keyConfig.HashAlgorithm, testDigest)
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
	case signer.HashAlgorithmSha256:
		break
	case signer.HashAlgorithmSha384:
		sum := sha512.Sum384(data)
		return crypto.SHA384, sum[:]
	case signer.HashAlgorithmSha512:
		sum := sha512.Sum512(data)
		return crypto.SHA512, sum[:]
	}
	sum := sha256.Sum256(data)
	return crypto.SHA256, sum[:]
}

func testSigner(t *testing.T, client *api.Client, keyType string, derived bool, keyConfig *signer.KeyConfig) (*signer.VaultSigner, error) {
	mountPath, keyName := createTransitMount(t, client, keyType, derived)
	config := keyConfig
	if keyConfig == nil {
		config = &signer.KeyConfig{}
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

	var tempDir string
	tempDir, err = ioutil.TempDir("", "derived_jwt")
	if err != nil {
		t.Error(err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "hashicorp/vault-enterprise",
		Tag:        "1.7.0-rc1_ent",
		Cmd: []string{"server", "-log-level=trace", "-dev", "-dev-three-node", fmt.Sprintf("-dev-root-token-id=%s", testToken),
			"-dev-listen-address=0.0.0.0:8200"},
		Env:    []string{"VAULT_DEV_TEMP_DIR=/tmp"},
		Mounts: []string{fmt.Sprintf("%s:/tmp", tempDir)},
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		t.Fatalf("Could not start local Vault docker container: %s", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("error removing temp directory: %s", err)
		}

		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	retAddress := fmt.Sprintf("https://127.0.0.1:%s", resource.GetPort("8200/tcp"))
	tlsConfig := &api.TLSConfig{
		CACert:     path.Join(tempDir, "ca_cert.pem"),
		ClientCert: path.Join(tempDir, "node1_port_8200_cert.pem"),
		ClientKey:  path.Join(tempDir, "node1_port_8200_key.pem"),
	}

	// exponential backoff-retry
	var client *api.Client
	if err = pool.Retry(func() error {
		vaultConfig := api.DefaultConfig()
		vaultConfig.Address = retAddress
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return err
		}
		client, err = api.NewClient(vaultConfig)
		if err != nil {
			return err
		}
		client.SetToken(testToken)

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
