# Split Route core

The engine behind the Split Route apps. It runs [sing-box](https://github.com/SagerNet/sing-box) in-process, so every
protocol sing-box supports is a tunnel, and it routes traffic by lists: direct, blocked, or through a chosen
tunnel. It stores nothing and has no UI; apps (macOS, Android, iOS, ...) own their storage and hand the engine a
`Config`.

Licensed GPL-3.0-or-later. sing-box and its libraries carry the same license, with a clause that no derivative may
use the name "sing-box"; this project does not.

## Packages

| Package | What it is |
|---|---|
| `core` (root) | `Config`, `Build` (Config to sing-box config, pure), `Engine` (start, stop, reload, status, events, challenges) |
| `ruleset` | One list as sing-box source rule-set files, written in place so sing-box reloads them without a restart |
| `rules` | Entries (CIDR, domain, suffix, AS number), parsing and validation, actions |
| `lists` | Parsing list files, hosts files and domain sets; downloading release lists with `SHA256SUMS` and size limits |
| `importers/openvpn` | `.ovpn` to the options of sing-box's OpenVPN client, fail-closed (mapped, ignorable, or refused by name) |

`rules`, `lists`, `ruleset` and `importers/...` do not import sing-box: they are cheap to depend on and test.

## Using the engine

```go
cfg := core.Config{
	Tunnels: []core.Tunnel{{ID: "office", Name: "Office", Protocol: "openvpn", Options: opts}}, // opts from an importer
	Lists:   []core.List{{ID: "ir", Name: "Iran", Action: rules.Direct}},
	WorkDir: "/path/private/to/the/app",
}
ruleset.Write(ruleset.Dir(cfg.WorkDir), "ir", rules.Direct, entries) // a list's contents, whenever they change

e, err := core.New(cfg)
err = e.Start()
for ev := range e.Events() { /* tunnel state, log lines */ }

restarted, err := e.Reload(newCfg) // restarts only if the sing-box config changed
```

A list's entries are not part of the config: change them with `ruleset.Write` and sing-box reloads the file. A
change to the lists' structure (a new list, another action or tunnel) or to the tunnels restarts the engine, which
reconnects every tunnel.

## Build tags

sing-box registers protocols by build tag. Build the app with `core.RequiredTags`:

```
go build -tags with_gvisor,with_quic,with_utls,with_wireguard,with_openvpn ./...
```

`Start` explains a missing tag. Without tags, `go test ./...` still runs the pure packages and the config tests.

## Tests

```
go test ./...                                   # pure packages and config
go test -tags with_gvisor,with_quic,with_utls,with_wireguard,with_openvpn ./...   # plus the engine
SPLITROUTE_TEST_PROFILE=client.ovpn go test -tags ... -run EngineLive .          # against a real OpenVPN server
```

The live test needs a certificate-only profile and its server (the engine runs in proxy mode, so no privileges).

## Targets

CI builds the engine for macOS, Linux, Windows, Android (arm64, cgo off) and iOS (arm64). Compilation is checked;
running on devices is not yet. See `docs/architecture.md` for the design, the untrusted-input rules and the risks.
