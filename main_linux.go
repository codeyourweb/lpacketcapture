//go:build linux

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/akamensky/argparse"
)

var activeInterfaces []listeningInterface
var err error
var blockingChannel = make(chan int)
var quitService chan struct{}

func main() {
	// config file argument parsing
	parser := argparse.NewParser("Local Packet Capture", "Listen to any interface and log traffic to a file or send it to an API endpoint.")
	configFilePath := parser.String("c", "config", &argparse.Options{Required: true, Help: "YAML configuration file"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// load yaml configuration
	err = LoadConfig(*configFilePath)
	if err != nil {
		log.Fatalln(fmt.Errorf("error loading configuration: %v", err))
	}

	// initialize logger
	var APP_LOGLEVEL int
	switch AppConfig.ApplicationLogLevel {
	case "LOGLEVEL_DEBUG":
		APP_LOGLEVEL = LOGLEVEL_DEBUG
	case "LOGLEVEL_WARNING":
		APP_LOGLEVEL = LOGLEVEL_WARNING
	case "LOGLEVEL_ERROR":
		APP_LOGLEVEL = LOGLEVEL_ERROR
	default:
		APP_LOGLEVEL = LOGLEVEL_INFO
	}
	InitLogger(APP_LOGLEVEL)
	if AppConfig.ApplicationLogFile != "" {
		SetLogToFile(AppConfig.ApplicationLogFile)
	}

	networkCaptureRoutine(quitService)
	<-blockingChannel
}
