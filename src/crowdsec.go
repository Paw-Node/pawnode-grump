package main

import (
	"net"
	"strings"
	"sync"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

// crowdsecBouncer maintains a live-updated set of banned IPs/ranges pulled
// from the CrowdSec Local API decision stream.
type crowdsecBouncer struct {
	mu        sync.RWMutex
	bannedIPs map[string]struct{}
	bannedNet []*net.IPNet
}

var bouncer *crowdsecBouncer

// initCrowdsec starts the CrowdSec stream bouncer in the background if
// enabled in config. Returns an error only on startup failure.
func initCrowdsec() error {
	if !config.CrowdsecEnabled {
		return nil
	}

	stream := &csbouncer.StreamBouncer{
		APIKey:         config.CrowdsecAPIKey,
		APIUrl:         config.CrowdsecAPIURL,
		TickerInterval: config.CrowdsecTickerInterval,
		UserAgent:      "grump-bouncer/" + buildVersion(),
	}

	if err := stream.Init(); err != nil {
		return err
	}

	bouncer = &crowdsecBouncer{bannedIPs: make(map[string]struct{})}

	go stream.Run(ctx)
	go func() {
		for decisions := range stream.Stream {
			bouncer.mu.Lock()
			for _, d := range decisions.Deleted {
				if d.Value == nil {
					continue
				}
				bouncer.removeLocked(*d.Value)
			}
			for _, d := range decisions.New {
				if d.Value == nil {
					continue
				}
				bouncer.addLocked(*d.Value)
			}
			bouncer.mu.Unlock()

			if len(decisions.New) > 0 || len(decisions.Deleted) > 0 {
				logJSON("info", "CrowdSec decisions updated", map[string]interface{}{
					"added":   len(decisions.New),
					"deleted": len(decisions.Deleted),
				})
			}
		}
	}()

	logJSON("info", "CrowdSec bouncer enabled", map[string]interface{}{"api_url": config.CrowdsecAPIURL})
	return nil
}

func (b *crowdsecBouncer) addLocked(value string) {
	if strings.Contains(value, "/") {
		if _, ipnet, err := net.ParseCIDR(value); err == nil {
			b.bannedNet = append(b.bannedNet, ipnet)
		}
		return
	}
	b.bannedIPs[value] = struct{}{}
}

func (b *crowdsecBouncer) removeLocked(value string) {
	if strings.Contains(value, "/") {
		for i, n := range b.bannedNet {
			if n.String() == value {
				b.bannedNet = append(b.bannedNet[:i], b.bannedNet[i+1:]...)
				return
			}
		}
		return
	}
	delete(b.bannedIPs, value)
}

// isBanned reports whether the given IP has an active CrowdSec ban decision.
// Always false when the bouncer is disabled.
func isBanned(ipStr string) bool {
	if bouncer == nil {
		return false
	}
	bouncer.mu.RLock()
	defer bouncer.mu.RUnlock()

	if _, ok := bouncer.bannedIPs[ipStr]; ok {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range bouncer.bannedNet {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
