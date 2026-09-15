package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type PortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Config struct {
	TargetCIDR           string         `json:"target_cidr"`
	RedisHost            string         `json:"redis_host"`
	RedisPort            int            `json:"redis_port"`
	RedisTTL             int            `json:"redis_ttl"`
	RedisPrefix          string         `json:"redis_prefix"`
	ListenAddr           string         `json:"listen_address"`
	MaxScansPerIP        int            `json:"max_scans_per_ip"`
	MaxScansPerIPTimeout int            `json:"max_scans_per_ip_timeout"`
	DisallowedHosts      []string       `json:"disallowed_hosts"`
	PortRanges           []PortRange    `json:"port_ranges"`
	Timeouts             map[string]int `json:"timeouts"`

	CrowdsecEnabled        bool   `json:"crowdsec_enabled"`
	CrowdsecAPIURL         string `json:"crowdsec_api_url"`
	CrowdsecAPIKey         string `json:"crowdsec_api_key"`
	CrowdsecTickerInterval string `json:"crowdsec_ticker_interval"`
}

// loadConfig reads and parses the given JSON config file into the global config.
func loadConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(&config)
}

func flattenPortRanges() []int {
	var ports []int
	for _, r := range config.PortRanges {
		for p := r.Start; p <= r.End; p++ {
			ports = append(ports, p)
		}
	}
	return ports
}

func formatPortList(portList []int) string {
	if len(portList) == 0 {
		return ""
	}
	result := ""
	start := portList[0]
	prev := portList[0]
	for i := 1; i <= len(portList); i++ {
		var curr int
		if i < len(portList) {
			curr = portList[i]
		} else {
			curr = portList[i-1] + 2
		}
		if curr != prev+1 {
			if start == prev {
				result += fmt.Sprintf("%d,", start)
			} else {
				result += fmt.Sprintf("%d-%d,", start, prev)
			}
			start = curr
		}
		prev = curr
	}
	return strings.TrimRight(result, ",")
}
