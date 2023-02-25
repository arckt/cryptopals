package main

import (
	"fmt"
	"crypt"
	"io/ioutil"
	"encoding/base64"
)

func main() {
	tmp, _ := ioutil.ReadFile("new")
	tmp2, _ := base64.StdEncoding.DecodeString(string(tmp))
	fmt.Println(string(crypt.BruteRepXor([]byte(tmp2), 2, 40)))
	return
}
