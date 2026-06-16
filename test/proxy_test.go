//go:build integration && proxy

package test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestChisel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping proxy test in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Proxy.Enabled {
		t.Skip("proxy tests disabled in config")
	}
	if cfg.Proxy.ChiselSource == "" {
		t.Skip("chisel_source not configured")
	}
	if !cfg.Remote.Enabled || !labctlAvailable() {
		t.Skip("remote testing not available")
	}

	// Build chisel server (local, no Win32).
	t.Log("building chisel server (local)...")
	server := WasmForgeBuild(t, cfg, cfg.Proxy.ChiselSource, BuildOpts{
		Verbose: true,
	})
	t.Logf("built chisel server in %v", server.Duration)

	// Build chisel client (Windows, Win32 APIs).
	t.Log("building chisel client (Windows)...")
	client := WasmForgeBuild(t, cfg, cfg.Proxy.ChiselSource, BuildOpts{
		GOOS:      "windows",
		GOARCH:    "amd64",
		Win32APIs: true,
	})
	t.Logf("built chisel client in %v", client.Duration)

	machine := cfg.Remote.Win11.Machine
	remotePath := cfg.Remote.Win11.WorkDir + `\chisel-test.exe`

	labctlKill(t, machine, "chisel-test.exe")
	labctlPush(t, client.Path, machine, remotePath, true)

	t.Cleanup(func() {
		labctlKill(t, machine, "chisel-test.exe")
		labctlCleanup(t, "kali")
	})

	// Verify SOCKS5 proxy connectivity.
	t.Run("socks5_verify", func(t *testing.T) {
		t.Skip("TODO: implement full chisel server/client lifecycle")

		socksAddr := "127.0.0.1:1080"
		transport := &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return socks5Dial(socksAddr, network, addr)
			},
		}
		httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

		resp, err := httpClient.Get(cfg.Proxy.TestURL)
		if err != nil {
			t.Fatalf("GET through SOCKS5: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "origin") {
			t.Errorf("response missing 'origin': %s", body)
		}
		t.Log("SOCKS5 proxy verified")
	})
}

func TestLigolo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping proxy test in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Proxy.Enabled {
		t.Skip("proxy tests disabled in config")
	}
	if cfg.Proxy.LigoloSource == "" {
		t.Skip("ligolo_source not configured")
	}
	if !cfg.Remote.Enabled || !labctlAvailable() {
		t.Skip("remote testing not available")
	}

	// Build ligolo agent (Windows).
	t.Log("building ligolo agent (Windows)...")
	agent := WasmForgeBuild(t, cfg, cfg.Proxy.LigoloSource, BuildOpts{
		GOOS:      "windows",
		GOARCH:    "amd64",
		Win32APIs: true,
	})
	t.Logf("built ligolo agent in %v", agent.Duration)

	// Build ligolo proxy (local).
	t.Log("building ligolo proxy (local)...")
	proxyBin := WasmForgeBuild(t, cfg, cfg.Proxy.LigoloSource, BuildOpts{
		Verbose: true,
	})
	t.Logf("built ligolo proxy in %v", proxyBin.Duration)

	t.Run("tunnel_verify", func(t *testing.T) {
		t.Skip("TODO: implement full ligolo proxy/agent lifecycle")
	})
}

// socks5Dial implements a minimal SOCKS5 CONNECT handshake (no auth).
func socks5Dial(proxyAddr, network, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// SOCKS5 greeting: version 5, 1 auth method (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting write: %w", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %x", buf)
	}

	// CONNECT request.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: status %d", resp[1])
	}

	return conn, nil
}
