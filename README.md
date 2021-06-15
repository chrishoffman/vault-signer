# vault-signer [![test](https://github.com/chrishoffman/vault-signer/workflows/test/badge.svg?branch=main)](https://github.com/chrishoffman/vault-signer/actions/workflows/test.yml)
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
