package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/gosimple/slug"
)

type listeningInterface struct {
	fullname     string
	device       pcap.Interface
	handle       *pcap.Handle
	packetsource *gopacket.PacketSource
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

func captureInterface(deviceName string, isPromiscuous bool, bpfFilter string) (*pcap.Handle, *gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(deviceName, 65536, isPromiscuous, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening interface %s: %v", deviceName, err)
	}

	if bpfFilter != "" {
		err = handle.SetBPFFilter(strings.TrimSpace(bpfFilter))
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
			if interfaceParams.Output.API.Enabled {
				normalizedPacket := normalizePacketInformations(networkInterface.fullname, srcIP, dstIP, srcPort, dstPort, protocol, payloadSize, message)
				messagesQueue = append(messagesQueue, *normalizedPacket)
			}

			if interfaceParams.Output.File.Enabled {
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

func createPCAPFile(interfaceDescription string, pcapFilePath string, linkType layers.LinkType) (*os.File, *pcapgo.Writer, error) {
	slugDescription := slug.Make(interfaceDescription)

	filename := fmt.Sprintf("%s/%s-%s.pcap", pcapFilePath, slugDescription, time.Now().Format("20060102150405"))
	pcapFile, err := os.Create(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("creating pcap file - %v", err)
	}

	pcapWriter := pcapgo.NewWriter(pcapFile)
	err = pcapWriter.WriteFileHeader(1024, linkType)

	if err != nil {
		return nil, nil, fmt.Errorf("writing pcap file header - %v", err)
	}

	return pcapFile, pcapWriter, nil
}

func filterInterfaces(devices []pcap.Interface, include InterfaceParams) ([]pcap.Interface, error) {
	var filteredDevices []pcap.Interface

	if (len(include.Name) == 0 && len(include.IPAddress) == 0) ||
		(len(include.Name) == 1 && len(include.IPAddress) == 1 && len(include.Name[0]) == 0 && len(include.IPAddress[0]) == 0) {
		return devices, nil
	}

	for _, device := range devices {
		for _, name := range include.Name {
			if len(name) == 0 {
				continue
			}

			if strings.Contains(device.Name, name) || strings.Contains(device.Description, name) {
				filteredDevices = append(filteredDevices, device)
			}
		}

		for _, ip := range include.IPAddress {
			if len(ip) == 0 {
				continue
			}

			for _, addr := range device.Addresses {
				if strings.Contains(addr.IP.String(), ip) {
					filteredDevices = append(filteredDevices, device)
				}
			}
		}
	}

	return filteredDevices, nil
}
