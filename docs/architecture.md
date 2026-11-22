# Core architecture

Status: the engine, `ruleset`, `rules`, `lists` and the OpenVPN importer are built and tested (see the README). Other protocols' importers, the mobile bindings and the `Platform` interface are not.

## Goal

A family of VPN apps (macOS first; Android and iOS next; Linux and Windows later) on one cross-platform Go
core. The core runs sing-box in-process, so every protocol sing-box supports (VLESS, VMess, Trojan,
Shadowsocks, Hysteria2, TUIC, WireGuard, OpenVPN, ...) is a tunnel. Routing is a feature of the VPN: lists decide
which traffic goes direct, is blocked, or goes through which tunnel.

Not a goal: routing other software's VPN (the old "route mode": kernel routes next to another VPN). It is removed.

## Who owns what

| Core (Go, no persistence, no UI) | Apps (one project per platform) |
|---|---|
| Engine lifecycle: start, stop, reload | Storage of tunnels, lists, settings |
| Typed config in, sing-box config out | Secrets (Keychain, Keystore) and credential prompts |
| Importers: links, subscriptions, `.ovpn`, WireGuard conf | UI and per-platform glue |
| List parsing and conversion to rule-sets, download helper | Tun device, VPN service or Network Extension, privileged service |
| Validation of everything that comes from outside | Updates and distribution |
| State and traffic events, logs | Presets and catalogs (content, not code) |

Importers live in the core as pure functions so every app parses and refuses the same things; they return typed
values and never touch storage.

## How the core runs sing-box

Embedded as a Go library (`github.com/sagernet/sing-box`, `box.New` with `include.Context`), one instance per
engine. All tunnels are outbounds or endpoints of that one instance; there are no per-tunnel processes, loopback
proxies or pid files. A tunnel change restarts the instance (proxy protocols reconnect at once, OpenVPN in about a
second); a change to a list's entries rewrites its rule-set file in place and sing-box reloads it.

Tunnel state comes from the library, not a CLI: the OpenVPN endpoint implements `adapter.OpenVPNEndpoint`
(`OpenVPNStatus()`, a `StatusUpdated()` channel, `CompleteChallenge`, `CancelChallenge`), which also covers MFA and
dynamic challenges.

## Core API (sketch)

```go
package core

type Engine struct{ /* unexported */ }

func New(p Platform, cfg Config) (*Engine, error) // validates; starts nothing
func (e *Engine) Start() error
func (e *Engine) Stop() error
func (e *Engine) Reload(cfg Config) (restarted bool, err error)
func (e *Engine) Events() <-chan Event // tunnel state, traffic, log lines
func (e *Engine) Status() Status
func (e *Engine) AnswerChallenge(tunnelID string, r ChallengeResponse) error

type Config struct {
	Tunnels []Tunnel // id, name, protocol, options (typed), secrets by value
	Lists   []List   // id, name, action direct|block|tunnel, tunnel id (empty: default), entries or rule-set
	Default string   // default tunnel id: unmatched traffic and unnamed tunnel lists
	DNS     DNS
	Tun     TunOptions
	WorkDir string // rule-set files; the app provides it
}

// Platform is what only the OS can do; the core ships a desktop implementation.
type Platform interface {
	OpenTun(TunOptions) (fd int, err error) // mobile: VpnService / NEPacketTunnelProvider
	Protect(fd int) error                   // keep the engine's own sockets out of the tun
	Network() NetworkMonitor                // default interface changes
}
```

Mobile gets a thin `mobile/` package for `gomobile bind` that takes and returns JSON strings (gomobile cannot
export these structs); the typed Go API is the source of truth.

### Routing semantics (carried over)

First match by tier: block, then direct, then tunnel; config order within a tier. A tunnel list whose tunnel is
not connected is rejected, never sent anywhere else. Unmatched traffic goes to the default tunnel.

## Untrusted input

A tunnel's options come from links, subscriptions and files, and the core runs in a privileged process. The core
validates them before anything starts:

- Per protocol, an allow-list of keys. Refuse file references (`*_path`, `certificate_path`, ...), `detour`,
  `bind_interface`, `routing_mark`, `protect_path`, `netns`, and anything that could read the disk or escape the
  engine's routing.
- Size and count limits (entries per list, tunnels, link length), like the imports today.
- OpenVPN keeps the fail-closed directive translation (`tunnel.SingboxEndpoint`): mapped, ignorable, or refused by name.
- Credentials are passed by value in memory and never logged or written by the core.

## What moves where (from the current repo)

| Today | Goes to |
|---|---|
| `internal/rules` (entries, parsing, floors) | core `rules` |
| `internal/lists` parse, import parsing, fetch with limits | core `lists` |
| `internal/tunnel` `profile.go`, `singbox.go` | core `importers/openvpn` |
| `internal/engine/tun` | core `engine` (rewritten for one instance, no loopback chain) |
| `internal/config`, `internal/store`, `internal/api`, `cmd/splitroute` | macOS repo (its own storage and socket API; a thin Go daemon hosts the core) |
| `macos/` (Swift app, build scripts, cask) | macOS repo |
| `internal/engine/route`, `state`, `platform` route socket, `splitroute up/down/watch` | deleted |
| `internal/tunnel` manager, management protocol, `ovpn3` helper, OpenVPN 2 launcher, `splitroute-engine` pinning | deleted (the library replaces them) |

## Verified by spike (2026-11-22)

- `github.com/sagernet/sing-box@v1.14.4` is importable as a library; with tags `with_gvisor,with_quic,with_wireguard,with_utls,with_openvpn` a minimal runner builds for darwin/arm64 (63 MB with more tags than needed), linux/amd64, windows/amd64, android/arm64 (CGO off) and ios/arm64 (Xcode toolchain, 47 MB).
- In-process, the OpenVPN endpoint connected to an OpenVPN 2.7 server and the rules applied (direct list 200, block list refused).
- The OpenVPN client is a separate module, `github.com/sagernet/sing-openvpn`. sing-box, sing-tun, sing and sing-openvpn carry the same author's license header.

## Not verified, and risks

- **Running on devices.** Only compilation was checked for iOS, Android, Windows. No `gomobile bind`, no device run.
- **iOS Network Extension memory** is tightly limited (tens of MB); gVisor and large rule-sets may not fit. Needs measuring early.
- **Apple Developer account.** iOS (and a macOS Network Extension) need a paid account; VPN apps on the App Store need an organization account (guideline 5.4). The macOS app stays outside the Store with a root service.
- **GPL and the App Store.** The core is GPL-3.0-or-later, and sing-box's license adds that no derivative may use its name. Distributing GPL code through the App Store is a known conflict with Apple's terms; get a legal opinion before an iOS release. Android (Play, F-Droid) and direct macOS distribution are fine.
- **sing-box API stability.** `box` and `libbox` are built for sing-box's own apps. Pin the version, wrap it behind the core's own types, and expect to adapt at upgrades.
- **Desktop tun needs root** (macOS, Linux) or admin (Windows); the privileged service is the app's job.
- **Reload semantics.** Today a changed config restarts the instance and drops every connection; a per-protocol hot update may be possible later.

## Repos

- `split-route/core`: the Go module (`github.com/split-route/core`), CI for all targets, tagged releases.
- `split-route/macos`: the Swift app and a small Go daemon that requires the core and exposes its own socket API.
- Later: `split-route/android`, `split-route/ios`, and the routing lists repo (`routing-rules`) if you want it under the org.
