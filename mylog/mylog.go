package mylog

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

var logger *log.Logger

func init() {
	log.SetFlags(log.LstdFlags)
}

func checkLog() {
	if logger == nil {
		SetLog(os.Stdout)
	}
}

func SetLogFile(logpath string, logname string) {
	var err error
	fpath, err := filepath.Abs(logpath)
	if err != nil {
		panic(err)
	}
	err = os.MkdirAll(fpath, 0666)
	if err != nil && !os.IsExist(err) {
		panic(err)
	}
	w, err := os.Create(filepath.Join(fpath, logname))
	if err != nil {
		panic(err)
	}
	SetLog(w)
}

func SetLog(w io.WriteCloser) {
	logger = log.New(w, "[gosyproxy] ", log.LstdFlags)
}

// These functions write to the standard logger.

// Print calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Print.
func Print(v ...any) {
	checkLog()
	logger.Print(v...)
}

// Printf calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Printf.
func Printf(format string, v ...any) {
	checkLog()
	logger.Printf(format, v...)
}

// Println calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Println.
func Println(v ...any) {
	checkLog()
	logger.Println(v...)
}

// Fatal is equivalent to Print() followed by a call to os.Exit(1).
func Fatal(v ...any) {
	checkLog()
	logger.Fatal(v...)
}

// Fatalf is equivalent to Printf() followed by a call to os.Exit(1).
func Fatalf(format string, v ...any) {
	checkLog()
	logger.Fatalf(format, v...)
}

// Fatalln is equivalent to Println() followed by a call to os.Exit(1).
func Fatalln(v ...any) {
	checkLog()
	logger.Fatalln(v...)
}

// Panic is equivalent to Print() followed by a call to panic().
func Panic(v ...any) {
	checkLog()
	logger.Panic(v...)
}

// Panicf is equivalent to Printf() followed by a call to panic().
func Panicf(format string, v ...any) {
	checkLog()
	logger.Panicf(format, v...)
}

// Panicln is equivalent to Println() followed by a call to panic().
func Panicln(v ...any) {
	checkLog()
	logger.Panicln(v...)
}
