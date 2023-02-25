package main

import(
	"fmt"
	"net/http/httptrace"
	"net/http"
	"time"
	"context"
	"log"
)
func timeGet(url string) time.Duration {
	    req, _ := http.NewRequest("GET", url, nil)

	        var start time.Time
		var ret time.Duration
		trace := &httptrace.ClientTrace{
			GotFirstResponseByte: func() {
				ret = time.Since(start)
			},
		}
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
																		       start = time.Now()
																		       if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
			log.Fatal(err)
		}
																			return ret
}


func main() {
	fmt.Println(int64(timeGet("http://localhost:8080/test")))
}
