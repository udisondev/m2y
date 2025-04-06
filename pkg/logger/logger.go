package logger

import (
	"fmt"
	"log"
	"os"
)

var (
	debugLog = log.New(os.Stdin, " |DEBUG| ", log.Ldate|log.Ltime|log.Lmsgprefix)
	infoLog  = log.New(os.Stdin, " |INFO| ", log.Ldate|log.Ltime|log.Lmsgprefix)
	warnLog  = log.New(os.Stdin, " |WARN| ", log.Ldate|log.Ltime|log.Lmsgprefix)
	errorLog = log.New(os.Stdin, " |ERROR| ", log.Ldate|log.Ltime|log.Lmsgprefix)
	level    = LDebug
)

const (
	LDebug int = iota
	LInfo
	LWarn
	LError
)

func Debugf(pref string, msg string, args ...any) {
	if level > LDebug {
		return
	}

	if pref != "" {
		msg = fmt.Sprintf("<%s> %s", pref, msg)
	}

	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args)
	}

	debugLog.Println(msg)
}

func Infof(pref string, msg string, args ...any) {
	if level > LInfo {
		return
	}

	if pref != "" {
		msg = fmt.Sprintf("<%s>: %s", pref, msg)
	}

	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args)
	}

	infoLog.Println(msg)
}

func Warnf(pref string, msg string, args ...any) {
	if level > LWarn {
		return
	}

	if pref != "" {
		msg = fmt.Sprintf("<%s>: %s", pref, msg)
	}

	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args)
	}

	warnLog.Println(msg)
}

func Errorf(pref string, msg string, args ...any) {
	if pref != "" {
		msg = fmt.Sprintf("<%s>: %s", pref, msg)
	}

	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args)
	}

	errorLog.Println(msg)
}
