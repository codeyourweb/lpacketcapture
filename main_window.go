//go:build windows

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/akamensky/argparse"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

var activeInterfaces []listeningInterface
var err error
var computerName string

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

	// start in interactive mode or as a Windows service
	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalln(fmt.Errorf("error checking if running in an interactive session or as a service: %v", err))
	}

	if isWindowsService {
		runService("nMonitorService", false)
	} else {
		logMessage(LOGLEVEL_INFO, "Running in interactive mode.")
		err = debug.Run("nMonitorService", &nMonitorService{})
		if err != nil {
			log.Fatalf("Error running service in interactive mode: %v", err)
		}
		return
	}
}
