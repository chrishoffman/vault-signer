package vaultsigner_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"math/big"
	"net"
	"path"
	"testing"
	"time"

	signer "github.com/chrishoffman/vault-signer"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
)

var _ crypto.Signer = (*signer.VaultSigner)(nil)
var enterprise = flag.Bool("enterprise", false, "Use Vault Enterprise")
var license = flag.String("license", "", "Vault Enterprise license")

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
	client := prepareTestContainer(t)

	t.Run("sign", func(t *testing.T) {
		t.Parallel()
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
			tt := tt
			signer, err := testSigner(t, client, tt.keyType, tt.derived, tt.signerConfig)
			if err != nil {
				t.Fatalf("error creating signer: %v", err)
			}

			testName := fmt.Sprintf("%s,derived:%t", tt.keyType, tt.derived)
			if tt.signerConfig != nil {
				if tt.signerConfig.SignatureAlgorithm != "" {
					testName += ":" + string(tt.signerConfig.SignatureAlgorithm)
				}
				if tt.signerConfig.HashAlgorithm != "" {
					testName += ":" + string(tt.signerConfig.HashAlgorithm)
				}
			}

			t.Run(testName, func(t *testing.T) {
				t.Parallel()
				testSign(t, signer, tt.keyType, tt.signerConfig, false)
			})

			t.Run(testName+",prehash", func(t *testing.T) {
				t.Parallel()
				testSign(t, signer, tt.keyType, tt.signerConfig, true)
			})
		}
	})

	t.Run("sign-examples", func(t *testing.T) {
		t.Parallel()
		t.Run("x509", func(t *testing.T) {
			t.Parallel()

			signerConfig := &signer.SignerConfig{
				HashAlgorithm:      signer.HashAlgorithmSha256,
				SignatureAlgorithm: signer.SignatureAlgorithmRSAPKCS1v15,
			}
			signer, err := testSigner(t, client, "rsa-4096", false, signerConfig)
			if err != nil {
				t.Fatalf("error creating signer: %v", err)
			}

			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test",
				},
				SerialNumber:       big.NewInt(1),
				NotAfter:           time.Now().Add(time.Hour).UTC(),
				SignatureAlgorithm: x509.SHA256WithRSA,
			}

			_, err = x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
			if err != nil {
				t.Fatalf("Error creating certificate: %s", err)
			}
		})

		t.Run("jwt", func(t *testing.T) {
			t.Parallel()

			var tests = []struct {
				keyType string
				algo    jose.SignatureAlgorithm
				config  *signer.SignerConfig
			}{
				{"ed25519", jose.EdDSA, nil},
				{"ecdsa-p256", jose.ES256, nil},
				{"rsa-4096", jose.RS256, nil},
				{"rsa-4096", jose.PS256, &signer.SignerConfig{SignatureAlgorithm: signer.SignatureAlgorithmRSAPSS}},
			}
			for _, tt := range tests {
				tt := tt
				t.Run(string(tt.algo), func(t *testing.T) {
					t.Parallel()

					vaultSigner, err := testSigner(t, client, tt.keyType, false, tt.config)
					if err != nil {
						t.Fatalf("error creating signer: %v", err)
					}
					testJWTSign(t, vaultSigner, tt.algo)
				})
			}
		})
	})

	t.Run("clone with context, not derived", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
		signer, err := testSigner(t, client, "ed25519", true, nil)
		if err != nil {
			t.Fatalf("error creating signer: %v", err)
		}

		clonedSigner, err := signer.CloneWithContext([]byte("abc"))
		if err != nil {
			t.Fatalf("should not be able to clone non-derived signer")
		}
		testSign(t, clonedSigner, "ed25519", nil, false)
	})

	t.Run("key does not support signing", func(t *testing.T) {
		t.Parallel()
		_, err := testSigner(t, client, "aes256-gcm96", true, nil)
		if err == nil {
			t.Fatalf("creating signer that does not support signing should have errored")
		}
	})

	t.Run("namespace support", func(t *testing.T) {
		if !*enterprise {
			t.Skip()
		}
		namespacePath := newUUID(t)
		if _, err := client.Logical().Write(path.Join("sys/namespaces", namespacePath), map[string]interface{}{}); err != nil {
			t.Fatalf("error creating namespace: %s", err)
		}

		client.SetNamespace(namespacePath)
		signer, err := testSigner(t, client, "ed25519", false, nil)
		if err != nil {
			t.Fatalf("error creating signer: %v", err)
		}
		testSign(t, signer, "ed25519", nil, false)

		// reset namespace
		client.SetNamespace("")
	})
}

func testSign(t *testing.T, vsigner *signer.VaultSigner, keyType string, signerConfig *signer.SignerConfig, prehash bool) {
	if signerConfig == nil {
		signerConfig = &signer.SignerConfig{}
	}

	publicKey := vsigner.Public()
	if publicKey == nil {
		t.Fatalf("invalid public key")
	}

	testDigest := []byte(newUUID(t))
	opts := crypto.Hash(0)
	algo, hash := hashValue(signerConfig.HashAlgorithm, testDigest)
	if prehash {
		testDigest = hash
		opts = algo
	}

	signature, err := vsigner.Sign(nil, testDigest, opts)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if len(signature) == 0 {
		t.Fatalf("invalid signature")
	}

	switch keyType {
	case "rsa-2048", "rsa-3072", "rsa-4096":
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
	default: // signer.HashAlgorithmSha256
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

func prepareTestContainer(t *testing.T) *api.Client {
	testUUID, err := uuid.NewUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testToken := testUUID.String()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	dockerImage := "hashicorp/vault"
	if *enterprise {
		dockerImage = "hashicorp/vault-enterprise"
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: dockerImage,
		Tag:        "latest",
		Cmd: []string{"server", "-log-level=trace", "-dev", fmt.Sprintf("-dev-root-token-id=%s", testToken),
			"-dev-listen-address=0.0.0.0:8200"},
		Env: []string{
			fmt.Sprintf("VAULT_LICENSE=%s", *license),
		},
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		t.Fatalf("Could not start local Vault docker container: %s", err)
	}

	t.Cleanup(func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	})

	var client *api.Client

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		vaultConfig := api.DefaultConfig()
		vaultPort := resource.GetPort("8200/tcp")

		// various installation of docker have different host and port settings, ensure
		// vault is listening before setting up client
		var dockerAddress string
		dockerHosts := []string{"172.17.0.1", "host.docker.internal", "127.0.0.1"}
		for _, host := range dockerHosts {
			dockerAddress = net.JoinHostPort(host, vaultPort)
			conn, err := net.DialTimeout("tcp", dockerAddress, time.Second)
			if err != nil {
				continue
			}
			if conn != nil {
				conn.Close()
			}
		}

		vaultConfig.Address = fmt.Sprintf("http://%s", dockerAddress)
		client, err = api.NewClient(vaultConfig)
		if err != nil {
			t.Fatalf("Failed to set up API client: %s", err)
		}
		client.SetToken(testToken)

		// Unmount default kv mount to ensure availability
		if err := client.Sys().Unmount("kv"); err != nil {
			return err
		}

		return nil
	}); err != nil {
		t.Fatalf("Could not connect to vault: %s", err)
	}

	return client
}

func testJWTSign(t *testing.T, vaultSigner *signer.VaultSigner, algo jose.SignatureAlgorithm) {
	// Set up JWT signer
	opaqueSigner := cryptosigner.Opaque(vaultSigner)
	signingKey := jose.SigningKey{Algorithm: algo, Key: opaqueSigner}
	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		t.Fatalf("error creating signer: %v", err)
	}

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

	rawJWT, err := builder.Serialize()
	if err != nil {
		t.Fatalf("failed to create JWT: %+v", err)
	}

	// decode the rawJWT and return a *JSONWebToken
	parsedJWT, err := jwt.ParseSigned(rawJWT, []jose.SignatureAlgorithm{algo})
	if err != nil {
		t.Fatalf("failed to parse JWT:%+v", err)
	}

	// Verify signature
	resultCl := map[string]interface{}{}
	if err := parsedJWT.Claims(vaultSigner.Public(), &resultCl); err != nil {
		t.Fatalf("Failed to verify JWT: %+v", err)
	}
}
