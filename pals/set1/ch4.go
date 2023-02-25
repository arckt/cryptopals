package main

import (
	"fmt"
	"crypt"
	"os"
	"bufio"
	"log"
	"encoding/hex"
)

type best struct {
	raw string
	score float64
	enc string
	key byte
}

func main() {
	file, err := os.Open("sinx")
	bes := best{"", 0, "", 0}
	if err != nil {
		log.Fatalf("failed to open file")
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		text := scanner.Text()
		tmp, _ := hex.DecodeString(text)
		s, sc, sk := crypt.BruteXor(tmp)

		if sc > bes.score {
			bes.score = sc
			bes.raw = s
			bes.enc = text
			bes.key = sk
		}
	}


	fmt.Println(bes.raw)
	return
}
