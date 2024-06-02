package license

import (
	"crypto/ed25519"
	"encoding/base64"
)

const DefaultPublicKey = "J7trVLsKRE2r+jRvCAHxycPjQbdwIm52+YU0jJo1KJM="

type Pair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func Generate() (*Pair, error) {
	p, pr, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &Pair{
		PublicKey:  base64.StdEncoding.EncodeToString(p),
		PrivateKey: base64.StdEncoding.EncodeToString(pr),
	}, nil
}
