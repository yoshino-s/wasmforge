// Package rawnet provides raw socket support for Go programs compiled with wasmforge.
//
// This package uses go:wasmimport to call wasmforge host functions for raw socket
// operations (SOCK_RAW). Raw sockets require the --raw-sockets flag when building
// with wasmforge and appropriate privileges (CAP_NET_RAW or root on Linux).
//
// Example usage:
//
//	conn, err := rawnet.Open(rawnet.AF_INET, rawnet.IPPROTO_ICMP)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer conn.Close()
//
//	n, err := conn.SendTo(packet, &rawnet.Addr4{IP: [4]byte{8, 8, 8, 8}})
package rawnet
