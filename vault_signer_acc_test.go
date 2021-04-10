package vaultsigner_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"

	vsigner "github.com/chrishoffman/vault-signer"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
)

func TestSign_RSA2048(t *testing.T) {
	cleanup, client := prepareTestContainer(t)
	defer cleanup()

	mountPath, keyName := createTransitMount(t, client, "rsa-2048", false)

	keyConfig := &vsigner.KeyConfig{
		MountPath: mountPath,
		KeyName:   keyName,
	}
	signer, err := vsigner.NewVaultSigner(client, keyConfig)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	testDigest := []byte("abc")
	signature, err := signer.Sign(nil, testDigest, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if len(signature) == 0 {
		t.Fatalf("invalid signature")
	}
}

func createTransitMount(t *testing.T, client *api.Client, keyType string, derived bool) (string, string) {
	mountPath := newUUID(t)
	t.Logf("creating transit mount: %s", mountPath)
	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Errorf("Error creating vault mount: %s", err)
	}

	// Create derived signing key
	keyName := newUUID(t)
	keyOptions := map[string]interface{}{
		"derived": derived,
		"type":    keyType,
	}
	log.Printf("creating key: %s", keyName)
	_, err := client.Logical().Write(path.Join(mountPath, "keys", keyName), keyOptions)
	if err != nil {
		t.Errorf("err: %s", err)
	}

	return mountPath, keyName
}

func newUUID(t *testing.T) string {
	generatedUUID, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("err: %s", err)
	}
	return generatedUUID.String()
}

func prepareTestContainer(t *testing.T) (func(), *api.Client) {
	testUUID, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("err: %s", err)
	}

	testToken := testUUID.String()
	t.Logf("generating test token: %s", testToken)

	var tempDir string
	tempDir, err = ioutil.TempDir("", "derived_jwt")
	if err != nil {
		t.Error(err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Errorf("Failed to connect to docker: %s", err)
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
		t.Errorf("Could not start local Vault docker container: %s", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("error removing temp directory: %s", err)
		}

		if err := pool.Purge(resource); err != nil {
			t.Errorf("Failed to cleanup local container: %s", err)
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
		t.Errorf("Could not connect to vault: %s", err)
	}
	return cleanup, client
}
