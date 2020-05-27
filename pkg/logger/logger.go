package logger


import(
	"fmt"
	"os"
	"io"
	"log"
)

type Logger struct {
	logger *log.Logger
	level int
}

var levels = map[string]int{
	"debug": 1,
	"info": 2,
	"warn": 3,
}

func (l *Logger) Init(logger *log.Logger, level string){
	l.level = levels[level]
	l.logger = logger
}

func (l *Logger) InitSimple(){
	mw := io.MultiWriter(os.Stdout)
	lg := log.New(mw, "", log.Ldate|log.Ltime|log.Lshortfile)
	l.level = 1
	l.logger = lg
}

func (l *Logger) Debug(logdata string, v ...interface{}){
	l.logger.Output(2, fmt.Sprintf(logdata, v...))
}

func (l *Logger) Info(logdata string, v ...interface{}){
	l.logger.Output(2, fmt.Sprintf(logdata, v...))
}

func (l *Logger) Warn(logdata string, v ...interface{}){
	l.logger.Output(2, fmt.Sprintf(logdata, v...))
}

func (l *Logger) Error(logdata string, v ...interface{}){
	l.logger.Output(2, fmt.Sprintf(logdata, v...))
}

func (l *Logger) Fatal(logdata string, v ...interface{}){
	l.logger.Output(2, fmt.Sprintf(logdata, v...))
	os.Exit(-1)
}