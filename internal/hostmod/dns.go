package hostmod

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/tetratelabs/wazero/api"
)

// sockGetaddrinfo implements the wasmforge.sock_getaddrinfo host function.
// Resolves DNS names using the host's resolver.
//
// Guest ABI:
//
//	name_ptr, name_len: hostname string
//	svc_ptr, svc_len:   service/port string (can be empty)
//	hints:              unused (reserved for future use)
//	result_ptr:         pointer to buffer for results
//	max_results:        max number of results to write
//	n_ptr:              pointer to write actual count of results
//
// Each result is written as:
//
//	[family:u16 LE] [socktype:u16 LE] [protocol:u16 LE] [addrlen:u16 LE] [addr:addrlen bytes]
//
// For simplicity, we write IPv4/IPv6 addresses directly.
func sockGetaddrinfo(ctx context.Context, mod api.Module, namePtr, nameLen, svcPtr, svcLen, hints, resultPtr, maxResults, nPtr uint32) uint32 {
	nameBuf, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	hostname := string(nameBuf)

	var service string
	if svcLen > 0 {
		svcBuf, ok := readBytes(mod, svcPtr, svcLen)
		if !ok {
			return errnoEFAULT
		}
		service = string(svcBuf)
	}

	// Use the host's resolver.
	addrs, err := net.DefaultResolver.LookupHost(context.Background(), hostname)
	if err != nil {
		writeUint32(mod, nPtr, 0)
		return errnoEAI
	}

	// Resolve the port if a service was specified.
	port := 0
	if service != "" {
		p, err := net.DefaultResolver.LookupPort(context.Background(), "tcp", service)
		if err == nil {
			port = p
		}
	}

	// Write results.
	offset := resultPtr
	count := uint32(0)

	for _, addrStr := range addrs {
		if count >= maxResults {
			break
		}

		ip := net.ParseIP(addrStr)
		if ip == nil {
			continue
		}

		// Each entry: [family:2][socktype:2][protocol:2][addrlen:2][addr:N]
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: 8-byte header + 8-byte addr = 16 bytes
			entry := make([]byte, 8+addrSizeIPv4)
			binary.LittleEndian.PutUint16(entry[0:2], addrFamilyIPv4)
			binary.LittleEndian.PutUint16(entry[2:4], 1)           // SOCK_STREAM
			binary.LittleEndian.PutUint16(entry[4:6], 6)           // IPPROTO_TCP
			binary.LittleEndian.PutUint16(entry[6:8], addrSizeIPv4) // addrlen
			// Write address in wire format.
			binary.LittleEndian.PutUint16(entry[8:10], addrFamilyIPv4)
			binary.BigEndian.PutUint16(entry[10:12], uint16(port))
			copy(entry[12:16], ip4)
			if !writeBytes(mod, offset, entry) {
				break
			}
			offset += uint32(len(entry))
			count++
		} else if ip6 := ip.To16(); ip6 != nil {
			// IPv6: 8-byte header + 28-byte addr = 36 bytes
			entry := make([]byte, 8+addrSizeIPv6)
			binary.LittleEndian.PutUint16(entry[0:2], addrFamilyIPv6)
			binary.LittleEndian.PutUint16(entry[2:4], 1)            // SOCK_STREAM
			binary.LittleEndian.PutUint16(entry[4:6], 6)            // IPPROTO_TCP
			binary.LittleEndian.PutUint16(entry[6:8], addrSizeIPv6) // addrlen
			// Write address in wire format.
			binary.LittleEndian.PutUint16(entry[8:10], addrFamilyIPv6)
			binary.BigEndian.PutUint16(entry[10:12], uint16(port))
			// flowinfo at [12:16] = 0
			copy(entry[16:32], ip6)
			// scope at [32:36] = 0
			if !writeBytes(mod, offset, entry) {
				break
			}
			offset += uint32(len(entry))
			count++
		}
	}

	writeUint32(mod, nPtr, count)
	return 0
}
