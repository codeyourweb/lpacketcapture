package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

var config lpacketcaptureConfig
var activeInterfaces []listeningInterface
var err error
var computerName string

func loadConfiguration(configObject *lpacketcaptureConfig, configFile string) error {
	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading yaml config file: %v", err)
	}

	err = yaml.Unmarshal(yamlFile, &configObject)
	if err != nil {
		return fmt.Errorf("error parsing yaml config file: %v", err)
	}

	return nil
}

func main() {
	SetLogLevel(LOGLEVEL_DEBUG)
	computerName, err = os.Hostname()
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Getting hostname - %v\n", err))
		os.Exit(1)
	}

	// Load configuration
	err = loadConfiguration(&config, "config.yaml")
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Loading configuration - %v\n", err))
		os.Exit(1)
	}

	// network interfaces listing
	logMessage(LOGLEVEL_INFO, "Starting network interfaces enumeration...\n")
	devices, err := listNetworkInterfaces()
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Listing network interfaces - %v\n", err))
		os.Exit(1)
	}

	if len(devices) == 0 {
		logMessage(LOGLEVEL_ERROR, "No network interfaces found.\n")
		os.Exit(1)
	}

	logMessage(LOGLEVEL_DEBUG, "Available network interfaces:\n")
	for _, device := range devices {
		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("%s\n", getInterfaceFullName(device)))
	}

	// interface filtering
	filteredInterfaces, err := filterInterfaces(devices, config.Interfaces.Include)
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Filtering network interfaces - %v\n", err))
		os.Exit(1)
	}

	if len(filteredInterfaces) == 0 {
		logMessage(LOGLEVEL_ERROR, "No network interfaces to listen.\n")
		os.Exit(1)
	}

	logMessage(LOGLEVEL_DEBUG, "Try to capture packets for the following network interfaces:\n")
	for _, device := range filteredInterfaces {
		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("%s\n", getInterfaceFullName(device)))
	}

	// capturing packets
	var blockingChannel = make(chan int)
	for _, device := range filteredInterfaces {
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("Starting packet capture on %s...\n", getInterfaceFullName(device)))
		handle, packetSource, err := captureInterface(device.Name, config.Filter)

		currentInterface := listeningInterface{
			fullname:     getInterfaceFullName(device),
			device:       device,
			handle:       handle,
			packetsource: packetSource,
		}

		activeInterfaces = append(activeInterfaces, currentInterface)

		if err != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Capturing packets - %v\n", err))
			os.Exit(1)
		}

		go packetListener(currentInterface)
	}

	// safe exit
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-signalChan
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("Received signal: %s\n", sig))

		for _, iface := range activeInterfaces {
			if iface.handle != nil {
				iface.handle.Close()
			}
		}

		if pcapFile != nil {
			pcapFile.Close()
		}
		logMessage(LOGLEVEL_INFO, "Exiting...\n")
		os.Exit(0)
	}()

	// periodically send packets to the API
	if config.Output.API.Enabled {
		for {
			sendPacketToUrlAddress()
			time.Sleep(5 * time.Second)
		}

	}

	<-blockingChannel
}
