package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// logJSON emits a structured "system" log line to stdout.
func logJSON(level, message string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"event_type": "system",
		"timestamp":  time.Now().Format(time.RFC3339),
		"level":      level,
		"message":    message,
	}
	for k, v := range fields {
		entry[k] = v
	}
	jsonEntry, _ := json.Marshal(entry)
	fmt.Println(string(jsonEntry))
}

// logFatal emits a fatal system log line and exits.
func logFatal(message string, fields map[string]interface{}) {
	logJSON("fatal", message, fields)
	os.Exit(1)
}

// logEvent emits a structured "connection" log line to stdout.
// dstIP may be "-" when no destination was resolved (banned, rate-limited, no target).
func logEvent(proto, result, srcIP string, srcPort int, dstIP string, dstPort int, extra map[string]interface{}) {
	if net.ParseIP(srcIP) == nil || (dstIP != "-" && net.ParseIP(dstIP) == nil) {
		logJSON("warn", "Malformed IP", map[string]interface{}{"src_ip": srcIP, "dst_ip": dstIP})
		return
	}

	event := map[string]interface{}{
		"event_type": "connection",
		"timestamp":  time.Now().Format(time.RFC3339),
		"proto":      proto,
		"result":     result,
		"src_ip":     srcIP,
		"src_port":   srcPort,
		"dst_ip":     dstIP,
		"dst_port":   dstPort,
	}

	for k, v := range extra {
		event[k] = v
	}

	jsonEvent, _ := json.Marshal(event)
	fmt.Println(string(jsonEvent))
}
