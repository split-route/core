# CLAUDE.md

`split-route/core`: the cross-platform engine behind the Split Route apps (macOS, later Android, iOS, Linux,
Windows). It runs sing-box in-process, so every protocol sing-box supports is a tunnel, and routes traffic by
lists. It stores nothing and has no UI; apps own storage, secrets and platform glue. It runs inside privileged
processes (a root service, a VPN service), so correctness and safety beat features. See `docs/architecture.md`.

## Layout

| Path | Role |
|------|------|
| `config.go`, `build.go` | `Config` and its validation (untrusted tunnel options are checked here); `Build` turns a Config into a sing-box config, purely and deterministically |
| `engine.go` | `Engine`: one sing-box instance; `Start`, `Stop`, `Reload`, `Status`, `Events`, challenges, `Test` (one timed request through a loaded tunnel) |
| `ruleset/` | One list as sing-box source rule-set files, written in place so sing-box reloads them |
| `rules/` | Entries (CIDR, domain, suffix, AS number), parsing and validation, actions |
| `lists/` | List files, hosts files, domain sets; release downloads with `SHA256SUMS` and limits |
| `importers/openvpn/` | `.ovpn` to sing-box's OpenVPN client options, fail-closed |
| `importers/links/` | Share links (vless, vmess, trojan, ss, hysteria2, tuic, anytls), base64 link lists and sing-box JSON to outbound options; per-node fail-closed, partial results |

## Rules

- `rules`, `lists`, `ruleset` and `importers/...` must not import sing-box: they stay cheap to depend on and test.
- Every list is two files (`<id>.json`, plus a names-only `<id>.dns.json` unless it blocks): sing-box treats IP
  entries in a DNS rule's rule-set as a deprecated answer filter. Write them in place (truncate and write), never
  by rename: sing-box reloads a rewritten file and doesn't notice a replaced one.
- All traffic no list names goes to one selector (`selected`) holding every tunnel, with `interrupt_exist_connections`.
  `Build` does not depend on `Config.Default`: the choice is made at run time (`Engine.Select`, and after every
  `Start`, because sing-box would otherwise use the first member or a cached selection; the config has no cache
  file for that reason). So switching the default tunnel never restarts the engine. Starting proxy tunnels is
  fast (about 30 ms for 5, 130 ms for 500; a restart 50 to 180 ms): keep it that way, `TestRestartAndStartAreFast...`.
- `Build` never depends on a list's entries, so editing a list never restarts the engine. A change to the lists'
  structure, the tunnels or the DNS does, and `Reload` says so.
- Tunnel options are untrusted: refuse `*_path` keys, `detour`, `bind_interface`, `routing_mark`, `protect_path`,
  `netns` and the other keys in `deniedKeys`, at any depth. The engine sets `tag`, `system` and `domain_resolver`
  itself. Importers are fail-closed: every directive is mapped, on a short ignorable list, or refused by name.
- A tunnel list whose tunnel isn't connected is never sent anywhere else: the endpoint refuses the connection.
- Lifecycle calls are serialized (`life` mutex); status is guarded by its own mutex and never held across a wait;
  events are best effort and never block or send on a closed channel. Run tests with `-race`.
- `links` importers refuse by name what the engine can't run (xhttp, mKCP, a reality link without its public key,
  hysteria2 `pinSHA256`, other flows) and never drop a security parameter; skip reasons and labels never repeat
  credentials. `TestImportedLinksStart` starts the real engine on every importer's output: add a fixture there
  for each new form, since `Validate` doesn't know sing-box's option schema.
- Never use `auth_retry: interact` for OpenVPN (it retries with empty credentials: account lockout).
- sing-box registers protocols by build tag: apps build with `core.RequiredTags`. Anything that starts the engine
  in a test needs the tags.
- Every bug fix gets a table test; parsers get a fixture copied from real output. English only.

## Verify

```sh
gofmt -l . && go vet ./... && go test -race ./...
T=with_gvisor,with_quic,with_utls,with_wireguard,with_openvpn
go vet -tags $T ./... && go test -race -tags $T ./...
SPLITROUTE_TEST_PROFILE=client.ovpn go test -race -tags $T -run EngineLive .   # live, needs a local server
```

CI also cross-compiles for linux, windows, android (cgo off) and ios.
