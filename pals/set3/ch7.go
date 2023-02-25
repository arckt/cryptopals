package main

import(
	//"time"
	//"fmt"
	"crypt/mersenne"
	//"strconv"
)

func main() {
	//val := time.Now().Unix()
	//tmp := make([]int, 624)
	//tmp2 := make([]int, 624)
	val2 := mersenne.Mt32()
	mersenne.UShiftRXr(val2)
	//fmt.Println(strconv.FormatUint(val3,2))
	//fmt.Println(strconv.FormatUint(0xffffffffffffffff,2))
	//for i := 0; i < 624; i++ {
	//	tmp[i] = mersenne.Mt32()
	//}

	//for i := 0; i < 624; i++ {
	//	tmp2[i] = mersenne.Utmpr(tmp[i])
	//	fmt.Println(i)
	//}
	
	//fmt.Println("DONE")
	//fmt.Printf("Time taken %ss", time.Now().Unix()-val)
}