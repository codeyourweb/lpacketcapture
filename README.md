# lpacketcapture - Local endpoint packets capture and netlog forwarding

## Description
This program was born out of a personal need to be able to log network traffic from local virtual machines and send some of this traffic to my SIEM (in my case, Sekoia). This program had to be minimalist, should not generate instability on the workstation and  consume a limited number of resources.

It implements the gopacket library for capture and offers logging possibilities in a pcap file (local or on a network drive) or sent directly by API (http post). pcap can be splitted to avoid heavy file size. Logs are sent with json dictionnary array every 5 seconds with following format:

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
* "interface_name" and "ipaddress" config parameters let you filter on selected interface s based on a *"contains"* condition
* "interface_name" and "ipaddress" also support regular expression (see capture2 example)
* you can filter your packet capture output with bpf syntax to filter capturing traffic
* pcap maxFileSize is expressed in MB
* /!\ YAML have to be indented **with spaces** , not tabs

```
application_log_level: "LOGLEVEL_INFO"         # use LOGLEVEL_DEBUG for more verbosity
application_log_file: ""                       # keep blank if you don't want the app to log its activity
interfaces:
    - capture_description: "capture1"          # add or remove entry for each capture criteria of your choice
      promiscuous_mode: true
      output:
          file:
              enabled: true
              maxFileSize: 1024
              filePath: "./"

    - capture_description: "capture2"
      interface_name: 
              - ""
      ipaddress:
              - "/^192\\.168\\.[0-1]\\.[0-9]{1,3}$/"
      promiscuous_mode: false
      bpf_filter: "tcp dst port 443"
      output:
          file:
              enabled: true
              maxFileSize: 1024
              filePath: "./"
          http:
              enabled: true
              url: "https://<your-api-endpoint>"
              headers:
                  Authorization: "Bearer YOUR_API_KEY"
                  MY-CUSTOM-HEADER: "My-Header-Value"
```

## Compilation instructions

You are not familiar with Go?
* Download the latest build at: https://go.dev/
* Git clone this repository
* run *go build -ldflags="-s -w" -o .* to compile it

## Last commit update
* Refactor configuration management and logging
* Introduced a new YAML configuration structure, allowing more config parameters for each capture
* Interfaces name or IP filter supports regular expression filtering
* Enhanced network capture functionality in networkcapture.go to support dynamic interface configuration and improved packet handling.
* Updated logger.go to enhance logging capabilities with new log levels and improved log formatting.
* Modified externaloutput.go to accept URL and headers as parameters for sending packets to an API.
* Added support for Windows service management in service_windows.go.
* Introduced slug generation for PCAP file naming to avoid issues with special characters.