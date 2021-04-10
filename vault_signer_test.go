package vaultsigner_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	signer "github.com/chrishoffman/vault-signer"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
)

var _ crypto.Signer = (*signer.VaultSigner)(nil)

func TestSign(t *testing.T) {
	cleanup, client := prepareTestContainer(t)
	defer cleanup()

	var tests = []struct {
		keyType string
		derived bool
	}{
		{"rsa-2048", false},
		{"rsa-3072", false},
		{"rsa-4096", false},
		{"ed25519", false},
		{"ed25519", true},
	}

	t.Run("sign", func(t *testing.T) {
		for _, tt := range tests {
			testName := fmt.Sprintf("%s,derived:%t", tt.keyType, tt.derived)
			t.Run(testName, func(t *testing.T) {
				t.Parallel()
				testSign(t, client, tt.keyType, tt.derived)
			})
		}
	})
}

func testSign(t *testing.T, client *api.Client, keyType string, derived bool) {
	mountPath, keyName := createTransitMount(t, client, keyType, derived)

	keyConfig := &signer.KeyConfig{
		MountPath: mountPath,
		KeyName:   keyName,
	}
	if derived {
		keyConfig.Context = []byte(newUUID(t))
	}
	signer, err := signer.NewVaultSigner(client, keyConfig)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	publicKey := signer.Public()
	if publicKey == nil {
		t.Fatalf("invalid public key")
	}

	testDigest := []byte(newUUID(t))
	signature, err := signer.Sign(nil, testDigest, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if len(signature) == 0 {
		t.Fatalf("invalid signature")
	}

	switch {
	case strings.HasPrefix(keyType, "rsa"):
		hash := sha256.Sum256(testDigest)
		rsaPublicKey := publicKey.(*rsa.PublicKey)
		if err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature); err != nil {
			t.Fatalf("signature does not verify")
		}
	case keyType == "ed25519":
		ed25519PublicKey := publicKey.(ed25519.PublicKey)
		if ok := ed25519.Verify(ed25519PublicKey, testDigest, signature); !ok {
			t.Fatalf("signature does not verify")
		}
	default:
		t.Fatalf("no verification function")
	}
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
