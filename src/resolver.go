package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func redisKey(parts ...string) string {
	return fmt.Sprintf("%s%s", config.RedisPrefix, strings.Join(parts, ":"))
}

func checkPortWithTimeout(ip net.IP, port int, timeout time.Duration) bool {
	if ip.To4() == nil {
		return false
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// resolveTargetIPWithCacheFlag finds a backend host serving the given port,
// preferring the Redis-cached mapping. The bool return reports a cache hit.
// On failure the returned IP is empty and reason is "RATE_LIMIT" or "NO_TARGET".
func resolveTargetIPWithCacheFlag(port int, clientIP string) (string, bool, string) {
	timeout := time.Second
	if ms, ok := config.Timeouts[fmt.Sprintf("%d", port)]; ok {
		timeout = time.Duration(ms) * time.Millisecond
	}

	cacheKey := redisKey("map", fmt.Sprintf("%d", port))
	cachedIP, err := redisClient.Get(ctx, cacheKey).Result()
	if err == nil && cachedIP != "" {
		ip := net.ParseIP(cachedIP)
		_, cidr, _ := net.ParseCIDR(config.TargetCIDR)
		if ip != nil && ip.To4() != nil && cidr.Contains(ip) && checkPortWithTimeout(ip, port, timeout) {
			return cachedIP, true, ""
		}
	}

	redisScanKey := redisKey("scan", clientIP)
	scanned, _ := redisClient.Incr(ctx, redisScanKey).Result()
	if scanned == 1 {
		redisClient.Expire(ctx, redisScanKey, time.Duration(config.MaxScansPerIPTimeout)*time.Second)
	}
	if scanned > int64(config.MaxScansPerIP) {
		return "", false, "RATE_LIMIT"
	}

	for _, ip := range targetIPs {
		if ip.To4() == nil {
			continue
		}
		skip := false
		for _, disallowed := range config.DisallowedHosts {
			if ip.String() == disallowed {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if checkPortWithTimeout(ip, port, timeout) {
			redisClient.Set(ctx, cacheKey, ip.String(), time.Duration(config.RedisTTL)*time.Second)
			return ip.String(), false, ""
		}
	}

	return "", false, "NO_TARGET"
}

// generateTargetIPs expands a CIDR into usable IPv4 host addresses,
// excluding the network and broadcast addresses.
func generateTargetIPs(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		if dup.To4() != nil {
			ips = append(ips, dup)
		}
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return []net.IP{}, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
