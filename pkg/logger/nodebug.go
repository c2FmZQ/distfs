//go:build !debug

package logger

// Debugf is compiled out in production builds.
func Debugf(format string, v ...any) {}

// Debugln is compiled out in production builds.
func Debugln(v ...any) {}
