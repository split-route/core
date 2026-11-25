package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Endpoint is where a tunnel's server is: what an app measures with a TCP connect or a ping, outside the tunnel.
type Endpoint struct {
	Host string // a name or an IP address
	Port int
	// UDP is set when the server speaks only UDP (WireGuard, Hysteria, TUIC, OpenVPN over UDP): a TCP connect to its port
	// means nothing.
	UDP bool
}

// udpProtocols are the protocols that carry nothing over TCP.
var udpProtocols = map[string]bool{"wireguard": true, "hysteria": true, "hysteria2": true, "tuic": true}

// TunnelEndpoint reads the server of a tunnel from its protocol and options (the ones an importer returned). An OpenVPN
// tunnel with several remotes gives the first; it is UDP only when no remote uses TCP.
func TunnelEndpoint(protocol string, options json.RawMessage) (Endpoint, error) {
	var o struct {
		Server     string `json:"server"`
		ServerPort any    `json:"server_port"`
		Servers    []struct {
			Server     string `json:"server"`
			ServerPort any    `json:"server_port"`
			Network    string `json:"network"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		return Endpoint{}, fmt.Errorf("the options aren't valid: %w", err)
	}
	if len(o.Servers) > 0 {
		s := o.Servers[0]
		port, ok := portNumber(s.ServerPort)
		if s.Server == "" || !ok {
			return Endpoint{}, errors.New("the server's address is missing")
		}
		udp := true
		for _, r := range o.Servers {
			if !strings.HasPrefix(strings.ToLower(r.Network), "udp") {
				udp = false
			}
		}
		return Endpoint{Host: s.Server, Port: port, UDP: udp}, nil
	}
	port, ok := portNumber(o.ServerPort)
	if o.Server == "" || !ok {
		return Endpoint{}, errors.New("the server's address is missing")
	}
	return Endpoint{Host: o.Server, Port: port, UDP: udpProtocols[protocol]}, nil
}

// portNumber reads a JSON port (a number or a numeric string) in 1-65535.
func portNumber(v any) (int, bool) {
	var n int
	switch x := v.(type) {
	case float64:
		n = int(x)
		if float64(n) != x {
			return 0, false
		}
	case string:
		var err error
		if n, err = strconv.Atoi(x); err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return n, n >= 1 && n <= 65535
}
