package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
)

const DefaultPublicKey = "J7trVLsKRE2r+jRvCAHxycPjQbdwIm52+YU0jJo1KJM="

type Pair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func (p *Pair) Store(name string) error {
	buf, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(name, buf, os.ModePerm)
}

func (p *Pair) Load(name string) error {
	buf, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, p)
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
