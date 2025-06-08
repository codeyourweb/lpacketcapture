package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/gosimple/slug"
)

var messagesQueue = []normalizedPacketInformation{}

type normalizedPacketInformation struct {
	Timestamp       string `json:"timestamp"`
	Hostname        string `json:"hostname"`
	InterfaceName   string `json:"interface_name"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationPort uint16 `json:"destination_port"`
	Protocol        string `json:"protocol"`
	PayloadSize     int    `json:"payload_size"`
	PacketData      string `json:"additional_data"`
}

func normalizePacketInformations(interfaceName string, srcIp string, dstIp string, srcPort uint16, dstPort uint16, proto string, pLen int, pData string) *normalizedPacketInformation {
	return &normalizedPacketInformation{
		Timestamp:       time.Now().UTC().Format("2006-01-02 15:04:05.000000"),
		Hostname:        computerName,
		InterfaceName:   interfaceName,
		SourceIP:        srcIp,
		DestinationIP:   dstIp,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		Protocol:        proto,
		PayloadSize:     pLen,
		PacketData:      pData,
	}
}

func sendPacketToUrlAddress(url string, headers *map[string]string) error {
	if len(messagesQueue) == 0 {
		return nil
	}

	sendingQueue := messagesQueue
	messagesQueue = []normalizedPacketInformation{}

	packetJSON, err := json.Marshal(sendingQueue)
	if err != nil {
		return fmt.Errorf("error marshaling packets to JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(packetJSON))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for key, value := range *headers {
			req.Header.Set(key, value)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending packet to URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error response from server: %d - %s", resp.StatusCode, resp.Status)
	}

	return nil
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
