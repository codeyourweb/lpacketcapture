package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var AppConfig Config

type Config struct {
	ApplicationLogLevel string            `yaml:"application_log_level"`
	ApplicationLogFile  string            `yaml:"application_log_file"`
	Interfaces          []InterfaceParams `yaml:"interfaces"`
}

type InterfaceParams struct {
	Description string   `yaml:"capture_description"`
	Name        []string `yaml:"interface_name"`
	Promiscuous bool     `yaml:"promiscuous"`
	Filter      string   `yaml:"bpf_filter"`
	IPAddress   []string `yaml:"ipaddress"`
	Output      Output   `yaml:"output"`
}

type Output struct {
	File FileOutput `yaml:"file"`
	API  APIOutput  `yaml:"api"`
}

type FileOutput struct {
	Enabled     bool   `yaml:"enabled"`
	MaxFileSize int    `yaml:"maxFileSize"`
	FilePath    string `yaml:"filePath"`
}

type APIOutput struct {
	Enabled bool               `yaml:"enabled"`
	URL     string             `yaml:"url"`
	Headers *map[string]string `yaml:"headers"`
}

func LoadConfig(configPath string) error {
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for config file '%s': %w", configPath, err)
	}

	configData, err := os.ReadFile(absConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file '%s': %w", absConfigPath, err)
	}

	err = yaml.Unmarshal(configData, &AppConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config data from '%s': %w", absConfigPath, err)
	}

	if AppConfig.ApplicationLogLevel == "" {
		AppConfig.ApplicationLogLevel = "LOGLEVEL_INFO"
	}
	AppConfig.ApplicationLogLevel = strings.ToUpper(AppConfig.ApplicationLogLevel)

	return nil
}
