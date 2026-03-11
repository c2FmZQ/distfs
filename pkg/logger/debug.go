//go:build debug

package logger

import "log"

// Debugf prints a formatted debug message.
func Debugf(format string, v ...any) {
	log.Printf(format, v...)
}

// Debugln prints a debug message.
func Debugln(v ...any) {
	log.Println(v...)
}
