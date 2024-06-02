package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type License struct {
	Product   string    `json:"product"`              //产品
	Domain    string    `json:"domain,omitempty"`     //域名，用于前端，支持多个
	MachineID string    `json:"machine_id,omitempty"` //机器ID，用于后端
	ExpireAt  time.Time `json:"expire_at,omitempty"`  //失效期

	Signature string `json:"signature,omitempty"` //签名
}

func (l *License) Sign(privateKey string) error {
	//复制证书
	ll := *l
	ll.Signature = ""

	//序列化
	msg, err := json.Marshal(&ll)
	if err != nil {
		return err
	}

	key, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return err
	}

	sign := ed25519.Sign(ed25519.PrivateKey(key), msg)
	l.Signature = base64.StdEncoding.EncodeToString(sign)

	return nil
}

func (l *License) Verify(publicKey string) error {
	//复制证书
	ll := *l
	ll.Signature = ""

	//序列化
	msg, err := json.Marshal(&ll)
	if err != nil {
		return err
	}

	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}

	sign, err := base64.StdEncoding.DecodeString(l.Signature)
	if err != nil {
		return err
	}

	ret := ed25519.Verify(ed25519.PublicKey(key), msg, sign)
	if !ret {
		return errors.New("签名错误")
	}

	return nil
}
