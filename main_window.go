//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

var activeInterfaces []listeningInterface
var err error
var computerName string

func networkCaptureRoutine(quitService chan struct{}) {
	// network interfaces listing
	logMessage(LOGLEVEL_INFO, "Starting network interfaces enumeration...")
	devices, err := listNetworkInterfaces()
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Listing network interfaces - %v", err))
		return
	}

	if len(devices) == 0 {
		logMessage(LOGLEVEL_ERROR, "No network interfaces found.")
		return
	}

	logMessage(LOGLEVEL_DEBUG, "Available network interfaces:")
	for _, device := range devices {
		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("%s\n", getInterfaceFullName(device)))
	}

	for _, configInterface := range AppConfig.Interfaces {
		// interface filtering
		filteredInterfaces, err := filterInterfaces(devices, configInterface)
		if err != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Filtering network interfaces - %v", err))
			return
		}

		if len(filteredInterfaces) == 0 {
			logMessage(LOGLEVEL_ERROR, "No network interfaces to listen.")
			return
		}

		logMessage(LOGLEVEL_DEBUG, "Try to capture packets for the following network interfaces:")
		for _, device := range filteredInterfaces {
			logMessage(LOGLEVEL_DEBUG, getInterfaceFullName(device))
		}

		// capturing packets
		for _, device := range filteredInterfaces {
			logMessage(LOGLEVEL_INFO, fmt.Sprintf("Starting packet capture on %s...", getInterfaceFullName(device)))
			handle, packetSource, err := captureInterface(device.Name, configInterface.Promiscuous, configInterface.Filter)

			if err != nil {
				logMessage(LOGLEVEL_ERROR, fmt.Sprintf("%s-%s : Capturing packets - %v", device.Name, device.Description, err))

				if handle == nil {
					continue
				}
			}

			currentInterface := listeningInterface{
				fullname:     getInterfaceFullName(device),
				device:       device,
				handle:       handle,
				packetsource: packetSource,
			}

			activeInterfaces = append(activeInterfaces, currentInterface)
			go packetListener(currentInterface, configInterface, quitService)
		}

		go func() {
			for {
				select {
				case <-quitService:
					logMessage(LOGLEVEL_INFO, "Received quit signal for network capture routine. Performing cleanup...")
					for _, iface := range activeInterfaces {
						if iface.handle != nil {
							iface.handle.Close()
							logMessage(LOGLEVEL_INFO, fmt.Sprintf("Closed handle for interface: %s", iface.fullname))
						}
					}
					logMessage(LOGLEVEL_INFO, "Network capture routine stopped.")
					return
				case <-time.After(5 * time.Second):
					if configInterface.Output.API.Enabled {
						sendPacketToUrlAddress(configInterface.Output.API.URL, configInterface.Output.API.Headers)
					}
				}
			}
		}()

	}
}

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
