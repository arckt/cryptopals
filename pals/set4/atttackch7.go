package main

import(
	"fmt"
	"net/http"
	"time"
	"net/http/httptrace"
	"log"

)

func timeGet(url string) time.Duration {
	fmt.Println(url)
	req, _ := http.NewRequest("GET", url, nil)
	var start time.Time
	var ret time.Duration
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			ret = time.Since(start)
		},
	}
	start = time.Now()
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
time.Sleep(time.Second)

	if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
		log.Fatal(err)
	}

	return ret
}


func main() {
	val := ""
	str := "0123456789abcdef"
	for i := 0; i < 40; i++ {
		tmp := ""
		arr := make([]int64,16)
		max := int64(0)

		for j := 0; j < len(str); j++ {
			total := int64(0)
			for h := 0; h < 10; h++ {
				value := int64(timeGet("http://localhost:8080/test?file=foo&signature="+val+string([]byte{str[j]})))
				total += value
			}
			arr[j] = total/10
		}

		for j := 0; j < len(str); j++ {
			if arr[j] > max {
				max = arr[j]
				tmp = string([]byte{str[j]})
			}
		}
		val += tmp
	}
	fmt.Printf("Signature found %s\n", val)
}
