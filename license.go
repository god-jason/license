package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/super-l/machine-code/machine"
	"strings"
	"time"
)

type License struct {
	Product   string    `json:"product"`              //产品
	Domain    string    `json:"domain,omitempty"`     //域名，用于前端，支持多个
	MachineID string    `json:"machine_id,omitempty"` //机器ID，用于后端
	ExpireAt  time.Time `json:"expire_at,omitempty"`  //失效期

	Signature string `json:"signature,omitempty"` //签名
}

func (l *License) Stringify() string {
	buf, _ := json.Marshal(l)
	return base64.StdEncoding.EncodeToString(buf)
}

func (l *License) Parse(lic string) error {
	buf, err := base64.StdEncoding.DecodeString(lic)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, l)
}

func (l *License) Serialize() string {
	var ss []string
	ss = append(ss, "p:", l.Product, "\n")
	ss = append(ss, "d:", l.Domain, "\n")
	ss = append(ss, "m:", l.MachineID, "\n")
	ss = append(ss, "e:", l.ExpireAt.Format(time.DateTime))
	return strings.Join(ss, "")
}

func (l *License) Sign(privateKey string) error {
	//序列化
	msg := l.Serialize()

	key, err := hex.DecodeString(privateKey)
	if err != nil {
		return err
	}

	sign := ed25519.Sign(key, []byte(msg))
	l.Signature = hex.EncodeToString(sign)

	return nil
}

func (l *License) Verify(publicKey string) error {
	//序列化
	msg := l.Serialize()

	key, err := hex.DecodeString(publicKey)
	if err != nil {
		return err
	}

	sign, err := hex.DecodeString(l.Signature)
	if err != nil {
		return err
	}

	ret := ed25519.Verify(key, []byte(msg), sign)
	if !ret {
		return errors.New("签名错误")
	}

	return nil
}

func (l *License) Expired() bool {
	return time.Now().After(l.ExpireAt)
}

func (l *License) Validate() error {
	cpuid, err := machine.GetCpuSerialNumber()
	if err != nil {
		return err
	}
	if l.MachineID != cpuid {
		return errors.New("机器码错误")
	}
	return nil
}
