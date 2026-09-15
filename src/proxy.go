package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func handleTCP(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, port))
	if err != nil {
		logFatal("TCP listen error", map[string]interface{}{"port": port, "error": err.Error()})
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			startTime := time.Now()
			defer c.Close()
			srcAddr := c.RemoteAddr().String()
			srcIP, srcPortStr, err := net.SplitHostPort(srcAddr)
			if err != nil {
				logJSON("warn", "Malformed source address", map[string]interface{}{"proto": "TCP", "src_addr": srcAddr, "dst_port": port})
				return
			}
			srcPort, err := strconv.Atoi(srcPortStr)
			if err != nil {
				logJSON("warn", "Malformed source address", map[string]interface{}{"proto": "TCP", "src_addr": srcAddr, "dst_port": port})
				return
			}

			if isBanned(srcIP) {
				logEvent("TCP", "BANNED", srcIP, srcPort, "-", port, nil)
				return
			}

			targetIP, fromCache, reason := resolveTargetIPWithCacheFlag(port, srcIP)
			if targetIP == "" {
				logEvent("TCP", reason, srcIP, srcPort, "-", port, nil)
				return
			}

			dstConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), time.Second)
			if err != nil {
				logEvent("TCP", "TIMEOUT", srcIP, srcPort, targetIP, port, nil)
				return
			}
			defer dstConn.Close()

			cacheStatus := "UNCACHED"
			if fromCache {
				cacheStatus = "CACHED"
			}

			logEvent("TCP", "ACCEPT", srcIP, srcPort, targetIP, port, map[string]interface{}{
				"duration_ms":  time.Since(startTime).Milliseconds(),
				"cache_status": cacheStatus,
			})

			go io.Copy(dstConn, c)
			io.Copy(c, dstConn)
		}(conn)
	}
}

func handleUDP(port int) {
	addr := net.UDPAddr{Port: port, IP: net.ParseIP(config.ListenAddr)}
	sock, err := net.ListenUDP("udp", &addr)
	if err != nil {
		logFatal("UDP listen error", map[string]interface{}{"port": port, "error": err.Error()})
	}
	defer sock.Close()

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if isBanned(clientAddr.IP.String()) {
			logEvent("UDP", "BANNED", clientAddr.IP.String(), clientAddr.Port, "-", port, nil)
			continue
		}

		targetIP, _, reason := resolveTargetIPWithCacheFlag(port, clientAddr.IP.String())
		if targetIP == "" {
			logEvent("UDP", reason, clientAddr.IP.String(), clientAddr.Port, "-", port, nil)
			continue
		}

		_, err = sock.WriteToUDP(buf[:n], &net.UDPAddr{IP: net.ParseIP(targetIP), Port: port})
		result := "RELAY"
		if err != nil {
			result = "ERROR"
		}
		logEvent("UDP", result, clientAddr.IP.String(), clientAddr.Port, targetIP, port, nil)
	}
}
