package main

import "runtime/debug"

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// buildVersion returns the injected version, falling back to VCS info
// embedded by the Go toolchain when building from a git checkout.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev string
		dirty := false
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if rev != "" {
			if len(rev) > 7 {
				rev = rev[:7]
			}
			if dirty {
				rev += "-dirty"
			}
			return rev
		}
	}
	return version
}
