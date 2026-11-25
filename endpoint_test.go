package core

import (
	"encoding/json"
	"testing"
)

func TestTunnelEndpoint(t *testing.T) {
	tests := []struct {
		name, protocol, options string
		want                    Endpoint
		wantErr                 bool
	}{
		{"vless", "vless", `{"type":"vless","server":"a.example","server_port":443}`, Endpoint{"a.example", 443, false}, false},
		{"port as string", "trojan", `{"server":"1.2.3.4","server_port":"8443"}`, Endpoint{"1.2.3.4", 8443, false}, false},
		{"hysteria2 is udp", "hysteria2", `{"server":"h.example","server_port":443}`, Endpoint{"h.example", 443, true}, false},
		{"tuic is udp", "tuic", `{"server":"t.example","server_port":4433}`, Endpoint{"t.example", 4433, true}, false},
		{"openvpn udp", "openvpn", `{"servers":[{"server":"o.example","server_port":1194,"network":"udp"}]}`, Endpoint{"o.example", 1194, true}, false},
		{"openvpn udp4 and udp6", "openvpn", `{"servers":[{"server":"o.example","server_port":1194,"network":"udp4"},{"server":"p.example","server_port":1195,"network":"udp6"}]}`, Endpoint{"o.example", 1194, true}, false},
		{"openvpn one tcp remote", "openvpn", `{"servers":[{"server":"o.example","server_port":1194,"network":"udp"},{"server":"p.example","server_port":443,"network":"tcp"}]}`, Endpoint{"o.example", 1194, false}, false},
		{"no server", "vless", `{"type":"vless"}`, Endpoint{}, true},
		{"port zero", "vless", `{"server":"a","server_port":0}`, Endpoint{}, true},
		{"port too big", "vless", `{"server":"a","server_port":70000}`, Endpoint{}, true},
		{"fractional port", "vless", `{"server":"a","server_port":44.5}`, Endpoint{}, true},
		{"not json", "vless", `nope`, Endpoint{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TunnelEndpoint(tc.protocol, json.RawMessage(tc.options))
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
