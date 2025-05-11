# lpacketcapture - Local endpoint packets capture and netlog forwarding

## Description
This program was born out of a personal need to be able to log network traffic from local virtual machines and send some of this traffic to my SIEM (in my case, Sekoia). This program had to be minimalist, should not generate instability on the workstation and should consume a limited number of resources on the workstations.

This program implements the gopacket library for capture and offers logging possibilities in a pcap file (local or on a network drive) or sent directly by API (http post). pcap files will can be splitted to avoid heavy file size. log are sent with json dictionnary array every 5 seconds with following format:

```
{
    "timestamp": "YYYY-MM-DD HH:mm:SS.000000",
    "hostname": "local_computer_hostname",
    "interface_name": "\\Device\\network_interface_name (network_interface_description)",
    "source_ip": "192.168.1.0",
    "destination_ip": "1.1.1.1",
    "source_port": 64315,
    "destination_port": 53,
    "protocol": "DNS",
    "payload_size": 16453,
    "additional_data": ""
}
```

## Configuration example

Here is a sample of my config.yaml 
* use bpf syntax to filter capturing traffic
* "include" can limit the capture to specific interface(s), based on names or ipaddresses
* "include"  is based on a *"contains"* condition either for name or ipaddress (example here: all interface containing "Virtual Ethernet adapter will be captured)
* let a empty string not to filter on a specific clause (example here: filter will not be based on ipaddress)
* pcap maxFileSize is expressed in MB
* /!\ YAML have to be indented **with spaces** , not tabs

```
filter: "tcp dst port 80 or tcp dst port 443 or udp dst port 53"
interfaces:
    include:
        name:
            - "Virtual Ethernet adapter"
        ipaddress:
            - ""
output:
    file:
        enabled: true
        maxFileSize: 1024
        filePath: "./"
    api:
        enabled: true
        url: "https://intake.sekoia.io/jsons"
        headers:
            X-SEKOIAIO-INTAKE-KEY: "<YOUR_INTAKE_KEY_HERE>"
```

## Compilation instructions

You are not familiar with Go?
* Download the latest build at: https://go.dev/
* Git clone this repository
* run *go build -ldflags="-s -w" -o .* to compile it