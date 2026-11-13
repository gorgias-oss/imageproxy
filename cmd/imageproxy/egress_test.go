// Copyright 2026 The imageproxy authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDenyPrivateAddress(t *testing.T) {
	tests := []struct {
		address string
		blocked bool
	}{
		{"8.8.8.8:443", false},
		{"[2001:4860:4860::8888]:443", false},
		{"[64:ff9b::808:808]:80", false}, // NAT64 for 8.8.8.8

		{"10.1.2.3:80", true},
		{"172.16.0.1:80", true},
		{"192.168.1.1:80", true},
		{"127.0.0.1:6379", true},
		{"100.64.0.1:80", true},
		{"169.254.169.254:80", true},
		{"0.0.0.0:80", true},
		{"[::1]:80", true},
		{"[::]:80", true},
		{"[fd00:ec2::254]:80", true},
		{"[fe80::1]:80", true},
		{"[::ffff:127.0.0.1]:80", true},
		{"[64:ff9b::a9fe:a9fe]:80", true}, // NAT64 for 169.254.169.254
	}
	for _, tt := range tests {
		err := denyPrivateAddress("tcp", tt.address, nil)
		if got := err != nil; got != tt.blocked {
			t.Errorf("denyPrivateAddress(%q) blocked = %v, want %v (err: %v)", tt.address, got, tt.blocked, err)
		}
	}
}

func TestPrivateNetworkDenyingTransport(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	port := origin.Listener.Addr().(*net.TCPAddr).Port

	client := &http.Client{Transport: privateNetworkDenyingTransport()}
	// literal IP, and a hostname that resolves to a loopback address
	for _, url := range []string{origin.URL, fmt.Sprintf("http://localhost:%d/", port)} {
		if resp, err := client.Get(url); err == nil {
			resp.Body.Close()
			t.Errorf("GET %s succeeded, want blocked", url)
		}
	}
}
