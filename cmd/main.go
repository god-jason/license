package main

import (
	"github.com/god-jason/license"
	"os"
	"time"
)

func main() {
	k, _ := license.Generate()

	lic := license.License{
		Product:   "master",
		MachineID: "123",
		ExpireAt:  time.Now().Add(time.Hour),
	}

	_ = lic.Sign(k.PrivateKey)

	_ = os.WriteFile("lic.txt", []byte(lic.Stringify()), os.ModePerm)

}
