package image

import (
	goauthn "github.com/google/go-containerregistry/pkg/authn"
)

func defaultKeychain() goauthn.Keychain {
	return goauthn.DefaultKeychain
}
