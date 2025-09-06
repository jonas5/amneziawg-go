package logger

import (
	"log"
	"os"
)

type Logger struct {
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

func DiscardLogf(format string, args ...any) {}

func NewLogger(level int, prepend string) *Logger {
	logger := &Logger{DiscardLogf, DiscardLogf}
	logf := func(prefix string) func(string, ...any) {
		return log.New(os.Stdout, prefix+": "+prepend, log.Ldate|log.Ltime).Printf
	}
	if level >= 2 {
		logger.Verbosef = logf("DEBUG")
	}
	if level >= 1 {
		logger.Errorf = logf("ERROR")
	}
	return logger
}
