package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

const banResponse = `{"new":[{"duration":"4h","origin":"crowdsec","scenario":"test/scan","scope":"Ip","type":"ban","value":"203.0.113.7"}],"deleted":[]}`

// fakeLAPI serves the decision stream, failing the first failFirst requests
// with a 503 before returning a single ban.
func fakeLAPI(t *testing.T, failFirst int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/decisions/stream") {
			http.NotFound(w, r)
			return
		}
		if calls.Add(1) <= failFirst {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(banResponse))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// useCrowdsecConfig points the bouncer at url for one test, and stops its
// background goroutines afterwards.
func useCrowdsecConfig(t *testing.T, url string) {
	t.Helper()
	prevConfig, prevBouncer, prevCtx := config, bouncer, ctx
	testCtx, cancel := context.WithCancel(context.Background())
	ctx = testCtx
	config = Config{
		CrowdsecEnabled:        true,
		CrowdsecAPIURL:         url,
		CrowdsecAPIKey:         "test",
		CrowdsecTickerInterval: "1s",
	}
	t.Cleanup(func() {
		cancel()
		config, bouncer, ctx = prevConfig, prevBouncer, prevCtx
	})
}

func waitForBan(t *testing.T, ip string, timeout time.Duration, calls *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !isBanned(ip) {
		if time.Now().After(deadline) {
			t.Fatalf("ban for %s never applied (%d stream calls)", ip, calls.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A LAPI that is down when grump starts must not leave the bouncer
// permanently without decisions. The library retries the first connection
// after 10s, so this test takes a little over that.
func TestCrowdsecRecoversFromUnavailableLAPIAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 10s initial-connect retry")
	}

	lapi, calls := fakeLAPI(t, 1)
	useCrowdsecConfig(t, lapi.URL)

	if err := initCrowdsec(); err != nil {
		t.Fatalf("initCrowdsec: %v", err)
	}

	waitForBan(t, "203.0.113.7", 20*time.Second, calls)
	if isBanned("198.51.100.1") {
		t.Fatal("unrelated IP reported as banned")
	}
}

// If a decision stream stops outright, the bouncer rebuilds it in-process
// instead of exiting or carrying on without bans.
func TestCrowdsecRestartsStoppedStream(t *testing.T) {
	lapi, calls := fakeLAPI(t, 1)
	useCrowdsecConfig(t, lapi.URL)

	prevNewStream, prevDelay := newStream, crowdsecRestartDelay
	t.Cleanup(func() { newStream, crowdsecRestartDelay = prevNewStream, prevDelay })
	crowdsecRestartDelay = 100 * time.Millisecond

	// The first stream does not retry its initial connect, so the 503 makes
	// Run return and the stream stop.
	var built atomic.Int32
	newStream = func() (*csbouncer.StreamBouncer, error) {
		s, err := newStreamBouncer()
		if err == nil && built.Add(1) == 1 {
			s.RetryInitialConnect = false
		}
		return s, err
	}

	if err := initCrowdsec(); err != nil {
		t.Fatalf("initCrowdsec: %v", err)
	}

	waitForBan(t, "203.0.113.7", 5*time.Second, calls)
	if n := built.Load(); n < 2 {
		t.Fatalf("expected the stream to be rebuilt, built %d", n)
	}
}

// The first response of a new stream is a full snapshot and must drop bans
// that were lifted while no stream was running.
func TestCrowdsecSnapshotReplacesStaleBans(t *testing.T) {
	prevBouncer := bouncer
	t.Cleanup(func() { bouncer = prevBouncer })

	ip := func(v string) *string { return &v }
	bouncer = &crowdsecBouncer{bannedIPs: make(map[string]struct{})}
	bouncer.apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{{Value: ip("192.0.2.1")}, {Value: ip("10.9.0.0/16")}},
	}, true)

	bouncer.apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{{Value: ip("203.0.113.7")}},
	}, true)

	if isBanned("192.0.2.1") || isBanned("10.9.1.1") {
		t.Fatal("stale bans survived a fresh snapshot")
	}
	if !isBanned("203.0.113.7") {
		t.Fatal("snapshot ban not applied")
	}

	bouncer.apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{{Value: ip("198.51.100.9")}},
	}, false)
	if !isBanned("203.0.113.7") || !isBanned("198.51.100.9") {
		t.Fatal("incremental update dropped existing bans")
	}
}
