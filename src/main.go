package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	ctx         = context.Background()
	targetIPs   []net.IP
	config      Config
)

func main() {
	if os.Geteuid() == 0 {
		logFatal("This program should not be run as root", nil)
	}
	logJSON("info", "GRUMP — Game Routing Unified Mapping Proxy", map[string]interface{}{"version": buildVersion()})

	if err := loadConfig("config.json"); err != nil {
		logFatal("Failed to load config.json", map[string]interface{}{"error": err.Error()})
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", config.RedisHost, config.RedisPort),
	})

	if _, err := redisClient.Ping(ctx).Result(); err != nil {
		logFatal("Failed to connect to Redis", map[string]interface{}{"error": err.Error()})
	}

	var err error
	targetIPs, err = generateTargetIPs(config.TargetCIDR)
	if err != nil || len(targetIPs) == 0 {
		fields := map[string]interface{}{"cidr": config.TargetCIDR}
		if err != nil {
			fields["error"] = err.Error()
		}
		logFatal("Invalid CIDR or no usable IPs", fields)
	}

	if err := initCrowdsec(); err != nil {
		logFatal("Failed to initialize CrowdSec bouncer", map[string]interface{}{"error": err.Error()})
	}

	ports := flattenPortRanges()
	logJSON("info", "Listening", map[string]interface{}{"proto": "TCP", "address": config.ListenAddr, "ports": formatPortList(ports)})
	logJSON("info", "Listening", map[string]interface{}{"proto": "UDP", "address": config.ListenAddr, "ports": formatPortList(ports)})
	for _, port := range ports {
		go handleTCP(port)
		go handleUDP(port)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	logJSON("info", "Shutting down gracefully", nil)
}
