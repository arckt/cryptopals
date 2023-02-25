package main

import (
	"crypt"
	"fmt"
)

func main() {
	tmp := crypt.FakeOracleBreak()
	fmt.Println(string(tmp))
}