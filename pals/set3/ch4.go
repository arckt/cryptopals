package main

import (
	"fmt"
	"crypt"
	"os"
	"bufio"
	"encoding/base64"
)

func main() {
	file := "b64"
	file2, err := os.Open(file)
	nonce := 0 
	key := crypt.RndStr(16)

	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(file2)
	scanner.Split(bufio.ScanLines)
	
	tmp := []string{}

	for scanner.Scan() {
		tmp2 := []byte{}
		text := scanner.Text()

		for _, c:= range text {
			tmp2 = append(tmp2, byte(c))
		}
		unkn, _ := base64.StdEncoding.DecodeString(string(tmp2))
		fmt.Println(string(unkn))
		unkn = crypt.AesCTR(unkn, key, uint64(nonce), 16)
		tmp = append(tmp, string(unkn))
	}
	fmt.Println("--------------------------")
	new2 := [][]byte{}
	crypt.StrSrt([]string(tmp))
	crypt.Reverse([]string(tmp))

	for _, c := range tmp {
		new2 = append(new2,[]byte(c))
	}
	
	new2 = crypt.Tpose(new2)
	new3 := [][]byte{}
	
	for _, c := range new2 {
		tmp2, _, _ := crypt.BruteXor(c)
		new3 = append(new3,[]byte(tmp2))
	}
	new4 := crypt.Tpose(new3)
	for _, c := range new4 {
		fmt.Println(string(c))
	}
	/*for i := 0; i < len(val)/min; i++ {
		fmt.Println(string(val[i*min:i*min+min]))
	}*/
}
