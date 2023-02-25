package main

import(
	"fmt"
	"crypt"
	"encoding/hex"
	"os"
	"log"
	"bufio"
)

func main() {
	tmp3 := [][]byte{}

	file, err := os.Open("hex.txt")
	
	if err != nil {
		log.Fatalf("failed to open file")
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		text, _ := hex.DecodeString(scanner.Text())
		tmp := []byte{}
		for _, c := range text {
			tmp = append(tmp, byte(c))
		}

		tmp3 = append(tmp3, tmp)
	}

	great := make([]int, 2)
	great[0] = 0
	great[1] = 0
	
	for i, c := range tmp3 {
		val := crypt.BloCnt(c, 16)
		if val > great[1] {
			great[0] = i
			great[1] = val
		}
	}

	fmt.Printf("Line number: %d\nOccurences: %d\n", great[0] + 1, great[1])
}