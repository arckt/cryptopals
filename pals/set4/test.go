package main

import (
	"fmt"
)

func main() {
	for i := 0; i < 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000; i++ {
		val1 := (56 - (i+1)%64)
		val2 := ((56 - (i+1)%64) % 64)
		if val1 != val2 {
			fmt.Println("DIFFERENCE DETECTED")
		}
	}
}
