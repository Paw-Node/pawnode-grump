package main

import (
	"net"
	"testing"
)

func TestFormatPortList(t *testing.T) {
	cases := []struct {
		name  string
		ports []int
		want  string
	}{
		{"empty", []int{}, ""},
		{"single", []int{25565}, "25565"},
		{"contiguous range", []int{25565, 25566, 25567}, "25565-25567"},
		{"mixed", []int{80, 443, 25565, 25566}, "80,443,25565-25566"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatPortList(tc.ports); got != tc.want {
				t.Errorf("formatPortList(%v) = %q, want %q", tc.ports, got, tc.want)
			}
		})
	}
}

func TestFlattenPortRanges(t *testing.T) {
	config.PortRanges = []PortRange{{Start: 25565, End: 25567}, {Start: 80, End: 80}}
	got := flattenPortRanges()
	want := []int{25565, 25566, 25567, 80}
	if len(got) != len(want) {
		t.Fatalf("expected %d ports, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestGenerateTargetIPs(t *testing.T) {
	ips, err := generateTargetIPs("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 has 4 addresses; network and broadcast are stripped
	if len(ips) != 2 {
		t.Fatalf("expected 2 usable IPs, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("192.168.1.1")) || !ips[1].Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("unexpected IPs: %v", ips)
	}

	if _, err := generateTargetIPs("not-a-cidr"); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestRedisKey(t *testing.T) {
	config.RedisPrefix = "grump:"
	if got := redisKey("map", "25565"); got != "grump:map:25565" {
		t.Errorf("redisKey = %q, want %q", got, "grump:map:25565")
	}
}
