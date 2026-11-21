package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A LAPI that is down when grump starts must not leave the bouncer
// permanently without decisions. The library retries the first connection
// after 10s, so this test takes a little over that.
func TestCrowdsecRecoversFromUnavailableLAPIAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 10s initial-connect retry")
	}

	var calls atomic.Int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/decisions/stream") {
			http.NotFound(w, r)
			return
		}
		if calls.Add(1) == 1 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"new":[{"duration":"4h","origin":"crowdsec","scenario":"test/scan","scope":"Ip","type":"ban","value":"203.0.113.7"}],"deleted":[]}`))
	}))
	defer lapi.Close()

	prevConfig, prevBouncer := config, bouncer
	defer func() { config, bouncer = prevConfig, prevBouncer }()

	config = Config{
		CrowdsecEnabled:        true,
		CrowdsecAPIURL:         lapi.URL,
		CrowdsecAPIKey:         "test",
		CrowdsecTickerInterval: "1s",
	}

	if err := initCrowdsec(); err != nil {
		t.Fatalf("initCrowdsec: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for !isBanned("203.0.113.7") {
		if time.Now().After(deadline) {
			t.Fatalf("ban never applied after LAPI came up (%d stream calls)", calls.Load())
		}
		time.Sleep(200 * time.Millisecond)
	}

	if isBanned("198.51.100.1") {
		t.Fatal("unrelated IP reported as banned")
	}
}
