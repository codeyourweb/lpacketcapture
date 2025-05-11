package main

type lpacketcaptureConfig struct {
	Filter     string     `yaml:"filter"`
	Interfaces Interfaces `yaml:"interfaces"`
	Output     Output     `yaml:"output"`
}

type Interfaces struct {
	Include IncludeFilter `yaml:"include"`
}

type IncludeFilter struct {
	Name      []string `yaml:"name"`
	IPAddress []string `yaml:"ipaddress"`
}

type Output struct {
	File OutputFile `yaml:"file"`
	API  OutputAPI  `yaml:"api"`
}

type OutputFile struct {
	Enabled     bool   `yaml:"enabled"`
	MaxFileSize int    `yaml:"maxFileSize"`
	FilePath    string `yaml:"filePath"`
}

type OutputAPI struct {
	Enabled bool              `yaml:"enabled"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}
