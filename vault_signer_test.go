package vaultsigner

import "crypto"

var _ crypto.Signer = (*VaultSigner)(nil)
