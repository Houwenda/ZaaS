package config

import (
	"errors"
	"io/ioutil"
	"os"
	"strconv"

	"gopkg.in/yaml.v2"
)

// Config cotains XdpConf and other subconfigurations.
type Config struct {
	LogConf       Log       `yaml:"log"`
	ServerConf    Server    `yaml:"server"`
	ZeekConf      Zeek      `yaml:"zeek"`
	SeaweedfsConf Seaweedfs `yaml:"seaweedfs"`
}

// Log is the config structure of logs
type Log struct {
	Path  string `yaml:"path"`
	Level string `yaml:"level"` // "debug"
}

type Server struct {
	RestAPIIP       string `yaml:"rest_api_ip"`
	RestAPIPort     int    `yaml:"rest_api_port"`
	RestAPIEndpoint string `yaml:"rest_api_endpoint"`
}

type Zeek struct {
	LogDir           string `yaml:"log_dir"`
	PcapDir          string `yaml:"pcap_dir"`
	ExtractedFileDir string `yaml:"extracted_file_dir"`
}

// Seaweedfs is the config structure of seaweedfs filer
type Seaweedfs struct {
	Addr             string `yaml:"address"`
	BasicUsername    string `yaml:"username"`
	BasicPassword    string `yaml:"password"`
	ExtractedFileDir string `yaml:"extracted_file_dir"`
	Retries          int    `yaml:"retries"`
}

// Parse reads config file and parse into Config struct.
func (c *Config) Parse(path string) (Config, error) {
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		return *c, err
	}
	// check file existence
	if _, existErr := os.Stat(path); existErr != nil && os.IsNotExist(existErr) {
		return *c, errors.New("config file does not exist at " + path)
	}
	// parse file
	err = yaml.Unmarshal(configFile, c)
	if err != nil {
		return *c, errors.New("config file cannot be parsed, check your syntax ")
	}
	return *c, err
}

// Validate checks Config struct for misconfigurations of analyzer.
func (c *Config) Validate() error {
	if c.ServerConf.RestAPIPort < 0 || c.ServerConf.RestAPIPort > 65535 {
		return errors.New("invalid restful port: " + strconv.Itoa(c.ServerConf.RestAPIPort))
	}

	// remove "/"
	c.ZeekConf.LogDir = processDirName(c.ZeekConf.LogDir)
	c.ZeekConf.PcapDir = processDirName(c.ZeekConf.PcapDir)
	c.ZeekConf.ExtractedFileDir = processDirName(c.ZeekConf.ExtractedFileDir)
	c.SeaweedfsConf.ExtractedFileDir = processDirName(c.SeaweedfsConf.ExtractedFileDir)

	if c.SeaweedfsConf.Retries < 1 {
		return errors.New("seaweedfs post retry times < 1")
	}
	return nil
}

// remove "/" at the end of directories
func processDirName(dirname string) string {
	if dirname[len(dirname)-1:] == "/" {
		return dirname[:len(dirname)-1]
	}
	return dirname
}
