package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
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

// crowdsecRestartDelay is how long to wait before rebuilding a decision
// stream that stopped. A var so tests can shorten it.
var crowdsecRestartDelay = 10 * time.Second

// newStream builds each decision stream the bouncer runs. A var so tests can
// substitute one that fails.
var newStream = newStreamBouncer

// initCrowdsec starts the CrowdSec stream bouncer in the background if
// enabled in config. Returns an error only for invalid configuration; once
// running, LAPI outages are retried in the background and never stop grump.
func initCrowdsec() error {
	if !config.CrowdsecEnabled {
		return nil
	}

	// Validate up front so a misconfiguration fails at startup rather than in
	// the restart loop.
	if _, err := newStreamBouncer(); err != nil {
		return err
	}

	bouncer = &crowdsecBouncer{bannedIPs: make(map[string]struct{})}
	go bouncer.run(ctx)

	logJSON("info", "CrowdSec bouncer enabled", map[string]interface{}{"api_url": config.CrowdsecAPIURL})
	return nil
}

func newStreamBouncer() (*csbouncer.StreamBouncer, error) {
	stream := &csbouncer.StreamBouncer{
		APIKey:         config.CrowdsecAPIKey,
		APIUrl:         config.CrowdsecAPIURL,
		TickerInterval: config.CrowdsecTickerInterval,
		UserAgent:      "grump-bouncer/" + buildVersion(),
		// Without this, a LAPI that is not answering yet when grump starts (boot
		// order, CrowdSec restarting) makes Run close the stream and return.
		RetryInitialConnect: true,
	}
	if err := stream.Init(); err != nil {
		return nil, err
	}
	return stream, nil
}

// run keeps a decision stream alive for the life of the process. If a stream
// stops it is rebuilt after crowdsecRestartDelay; the last known bans stay in
// force in the meantime, and proxying carries on throughout.
func (b *crowdsecBouncer) run(ctx context.Context) {
	for {
		stream, err := newStream()
		if err == nil {
			err = b.consume(ctx, stream)
		}
		if ctx.Err() != nil {
			return
		}

		fields := map[string]interface{}{"retry_in": crowdsecRestartDelay.String()}
		if err != nil {
			fields["error"] = err.Error()
		}
		logJSON("error", "CrowdSec decision stream stopped, restarting", fields)

		select {
		case <-ctx.Done():
			return
		case <-time.After(crowdsecRestartDelay):
		}
	}
}

// consume applies decisions from one stream until it stops. The first
// response of a stream is the LAPI's full snapshot, so it replaces whatever
// was held from a previous stream instead of merging into it.
func (b *crowdsecBouncer) consume(ctx context.Context, stream *csbouncer.StreamBouncer) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("decision stream panicked: %v", r)
			}
		}()
		done <- stream.Run(ctx)
	}()

	snapshot := true
	for {
		select {
		case err := <-done:
			return err
		case decisions, ok := <-stream.Stream:
			if !ok {
				return <-done
			}
			b.apply(decisions, snapshot)
			snapshot = false
		}
	}
}

func (b *crowdsecBouncer) apply(decisions *models.DecisionsStreamResponse, snapshot bool) {
	if decisions == nil {
		return
	}

	b.mu.Lock()
	if snapshot {
		b.bannedIPs = make(map[string]struct{})
		b.bannedNet = nil
	}
	for _, d := range decisions.Deleted {
		if d.Value == nil {
			continue
		}
		b.removeLocked(*d.Value)
	}
	for _, d := range decisions.New {
		if d.Value == nil {
			continue
		}
		b.addLocked(*d.Value)
	}
	total := len(b.bannedIPs) + len(b.bannedNet)
	b.mu.Unlock()

	if snapshot || len(decisions.New) > 0 || len(decisions.Deleted) > 0 {
		logJSON("info", "CrowdSec decisions updated", map[string]interface{}{
			"added":    len(decisions.New),
			"deleted":  len(decisions.Deleted),
			"snapshot": snapshot,
			"total":    total,
		})
	}
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
