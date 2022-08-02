package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/topcoder520/gosyproxy/hdlwraper"
	"github.com/topcoder520/gosyproxy/mylog"
)

var Port int

func init() {
	flag.IntVar(&Port, "p", 8888, "port")
}

func main() {
	flag.Parse()

	mylog.SetLog(os.Stdout)

	mylog.Println("listening server port ", Port)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", Port),
		Handler:      hdlwraper.NewHdlwraper(),
		ReadTimeout:  time.Minute * 10,
		WriteTimeout: time.Minute * 10,
	}
	if err := server.ListenAndServe(); err != nil {
		mylog.Fatalln(err)
	}
}
