package main

import (
	"encoding/json"
	"github.com/god-jason/license"
	"os"
)

func main() {
	k, _ := license.Generate()
	b, _ := json.Marshal(k)
	_ = os.WriteFile("license.json", b, 0644)
}
