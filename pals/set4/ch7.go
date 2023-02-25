package main

import(
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"
	"crypt"
)

func insecureCompare(val1, val2 []byte) bool {
	res := fmt.Sprintf("%x", val1)
	fmt.Println(res)
	//fmt.Println(string(val2))
	for i := 0; i < len(val2); i++ {
		fmt.Println(i)
		if val2[i] != res[i] {
			fmt.Println(i)
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

func handler(w http.ResponseWriter, r * http.Request) {
	path := r.RequestURI[:]
	fmt.Println(path)
	fileReg, _ := regexp.Compile("file=([a-z]+)&")
	sigReg, _ := regexp.Compile("signature=([a-z0-9]+)")
	fileName := []byte(fileReg.FindString(path))
	sig := []byte(sigReg.FindString(path))
	signat := sig[10:]
	filen := fileName[5:len(fileName)-1]
	val := insecureCompare(crypt.HMACSHA1([]byte("KEY"), []byte(filen)), []byte(signat))
	fmt.Println([]byte(crypt.HMACSHA1([]byte("KEY"), []byte(filen))))
	if val {
		http.Redirect(w, r, "wow", 200)
	} else {
		http.Redirect(w, r, "no", 500)
	}
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
