package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type listeningInterface struct {
	fullname     string
	device       pcap.Interface
	handle       *pcap.Handle
	packetsource *gopacket.PacketSource
}

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
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("%s : Filtering network interfaces - %v", configInterface.Description, err))
			return
		}

		if len(filteredInterfaces) == 0 {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("%s : No network interfaces to listen.", configInterface.Description))
			return
		}

		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("%s : Try to capture packets for the following network interfaces:", configInterface.Description))
		for _, device := range filteredInterfaces {
			logMessage(LOGLEVEL_DEBUG, getInterfaceFullName(device))
		}

		// capturing packets
		for _, device := range filteredInterfaces {
			logMessage(LOGLEVEL_INFO, fmt.Sprintf("%s : Starting packet capture on %s...", configInterface.Description, getInterfaceFullName(device)))
			handle, packetSource, err := captureInterface(device.Name, configInterface.Promiscuous, configInterface.Filter)

			if err != nil {
				logMessage(LOGLEVEL_ERROR, fmt.Sprintf("%s : %s-%s : Capturing packets - %v", configInterface.Description, device.Name, device.Description, err))

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
					if configInterface.Output.API != nil && configInterface.Output.API.Enabled {
						sendPacketToUrlAddress(configInterface.Output.API.URL, configInterface.Output.API.Headers)
					}
				}
			}
		}()

	}
}

func getInterfaceFullName(device pcap.Interface) string {
	interfaceFullName := device.Name
	if device.Description != "" {
		interfaceFullName += fmt.Sprintf(" (%s)", device.Description)
	}
	return interfaceFullName
}

func listNetworkInterfaces() (dev []pcap.Interface, err error) {
	dev, err = pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("error finding devices: %v", err)
	}

	return dev, nil
}

func captureInterface(deviceName string, isPromiscuous bool, bpfFilter *string) (*pcap.Handle, *gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(deviceName, 65536, isPromiscuous, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening interface %s: %v", deviceName, err)
	}

	if bpfFilter != nil && *bpfFilter != "" {
		err = handle.SetBPFFilter(strings.TrimSpace(*bpfFilter))
		if err != nil {
			handle.Close()
			return nil, nil, fmt.Errorf("BPF filter: %s - %v", err, bpfFilter)
		}
	}

	return handle, gopacket.NewPacketSource(handle, handle.LinkType()), nil
}

func packetListener(networkInterface listeningInterface, interfaceParams InterfaceParams, quitService chan struct{}) {
	packetSourceDone := make(chan struct{})
	var pcapFile *os.File
	var pcapWriter *pcapgo.Writer

	go func() {
		for packet := range networkInterface.packetsource.Packets() {
			var srcIP, dstIP string
			var srcPort, dstPort uint16
			var protocol string
			var payloadSize int
			var message string

			// IP Layer
			if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
				ip4, _ := ip4Layer.(*layers.IPv4)
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
				payloadSize = int(ip4.Length)
			} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
				ip6, _ := ip6Layer.(*layers.IPv6)
				srcIP = ip6.SrcIP.String()
				dstIP = ip6.DstIP.String()
				payloadSize = int(ip6.Length)
			}

			// TCP Layer
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
				protocol = "TCP"
				logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("[%s -> %s] %s %d -> %d (Length: %d bytes)\n", srcIP, dstIP, protocol, srcPort, dstPort, payloadSize))
			}

			// UDP Layer
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
				protocol = "UDP"

				// DNS Layer
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					protocol = "DNS"
					for _, q := range dns.Questions {
						message += fmt.Sprintf(" (DNS question: %s [%s])", string(q.Name), q.Type)
					}
					for _, a := range dns.Answers {
						message += fmt.Sprintf(" (DNS answer: %s -> %s [%s])", string(a.Name), a.IP, a.Type)
					}
				}

				logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("[%s -> %s] %s %d -> %d (Length: %d bytes)%s\n",
					srcIP, dstIP, protocol, srcPort, dstPort, payloadSize, message))
			}

			// external output
			if interfaceParams.Output.API != nil && interfaceParams.Output.API.Enabled {
				normalizedPacket := normalizePacketInformations(networkInterface.fullname, srcIP, dstIP, srcPort, dstPort, protocol, payloadSize, message)
				messagesQueue = append(messagesQueue, *normalizedPacket)
			}

			if interfaceParams.Output.File != nil && interfaceParams.Output.File.Enabled {
				if pcapFile == nil {
					pcapFile, pcapWriter, err = createPCAPFile(interfaceParams.Description, interfaceParams.Output.File.FilePath, networkInterface.handle.LinkType())
					if err != nil {
						logMessage(LOGLEVEL_ERROR, fmt.Sprintf("pcap - %v\n", err))
						return
					}
				} else {
					fileInfo, err := pcapFile.Stat()
					if err != nil {
						logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Error getting file info - %v\n", err))
					}

					if fileInfo.Size() > int64(interfaceParams.Output.File.MaxFileSize*1024*1024) {
						pcapFile.Close()
						pcapFile, pcapWriter, err = createPCAPFile(interfaceParams.Description, interfaceParams.Output.File.FilePath, networkInterface.handle.LinkType())
						if err != nil {
							logMessage(LOGLEVEL_ERROR, fmt.Sprintf("pcap - %v\n", err))
							return
						}
					}
				}

				if pcapWriter != nil {
					err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
					if err != nil {
						logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Error writing packet to pcap file: %v\n", err))
					}

					pcapFile.Sync()
				}
			}
		}
		close(packetSourceDone)
	}()

	select {
	case <-packetSourceDone:
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("Packet listener for %s finished.", networkInterface.fullname))
		pcapFile.Close()
	case <-quitService:
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("Packet listener for %s received quit signal.", networkInterface.fullname))
		pcapFile.Close()
	}
}

func filterInterfaces(devices []pcap.Interface, include InterfaceParams) ([]pcap.Interface, error) {
	var filteredDevices []pcap.Interface

	if include.Name == nil && include.IPAddress == nil {
		return devices, nil
	}

	for _, device := range devices {

		if include.Name != nil {
			for _, name := range *include.Name {
				if len(name) == 0 {
					continue
				}

				if strings.HasPrefix(name, "/") && strings.HasSuffix(name, "/") {
					// Regular expression match
					regex, err := regexp.Compile(strings.Trim(name, "/"))
					if err != nil {
						return nil, fmt.Errorf("invalid regular expression '%s': %v", name, err)
					}

					if regex.MatchString(device.Name) || regex.MatchString(device.Description) {
						filteredDevices = append(filteredDevices, device)
					}
				} else {
					if strings.Contains(device.Name, name) || strings.Contains(device.Description, name) {
						filteredDevices = append(filteredDevices, device)
					}
				}
			}
		}

		if include.IPAddress != nil {
			for _, ip := range *include.IPAddress {
				if len(ip) == 0 {
					continue
				}

				for _, addr := range device.Addresses {

					if strings.HasPrefix(ip, "/") && strings.HasSuffix(ip, "/") {
						// Regular expression match
						regex, err := regexp.Compile(strings.Trim(ip, "/"))
						if err != nil {
							return nil, fmt.Errorf("invalid regular expression '%s': %v", ip, err)
						}

						if regex.MatchString(addr.IP.String()) {
							filteredDevices = append(filteredDevices, device)
						}
					} else {
						if strings.Contains(addr.IP.String(), ip) {
							filteredDevices = append(filteredDevices, device)
						}
					}

				}
			}
		}
	}

	return filteredDevices, nil
}
