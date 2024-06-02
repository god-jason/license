package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
)

const DefaultPublicKey = "1d858f2f7270a7fd1e51acc61251aa38f4ee6dc8f5973a50a11381279e5770be"

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
		PublicKey:  hex.EncodeToString(p),
		PrivateKey: hex.EncodeToString(pr),
	}, nil
}
