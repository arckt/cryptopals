package main

import(
	"fmt"
	"encoding/base64"
	"os"
	"log"
	"bufio"
	"crypt"
)

func main() {
	key := "YELLOW SUBMARINE"

	tmp := crypt.Conv("b642.txt")
	
	tmp2, _ := base64.StdEncoding.DecodeString(string(tmp))

	fmt.Println(string(crypt.DecryptAesEcb(tmp2, []byte(key))))
}