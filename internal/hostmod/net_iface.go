package hostmod

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/tetratelabs/wazero/api"
)

// netInterfaces implements the wasmforge.net_interfaces host function.
// Serializes real network interfaces to a WASM buffer.
//
// Guest ABI:
//
//	buf_ptr:        pointer to output buffer
//	buf_cap:        capacity of output buffer
//	result_len_ptr: pointer to write actual length of serialized data
//
// Serialization format:
//
//	uint32: count of interfaces
//	For each interface:
//	  uint32: index
//	  uint32: MTU
//	  uint32: flags
//	  uint32: len(name)
//	  []byte: name
//	  uint32: len(hardwareAddr)
//	  []byte: hardwareAddr
//	  uint32: count of addresses
//	  For each address:
//	    uint32: len(addr_string)
//	    []byte: addr_string (CIDR notation, e.g. "192.168.1.1/24")
//
// Returns WASI errno (0 = success).
func netInterfaces(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	resultLenPtr := uint32(stack[2])

	ifaces, err := net.Interfaces()
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	// Serialize interfaces into a buffer.
	buf := make([]byte, 0, 4096)

	// Write interface count.
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(len(ifaces)))
	buf = append(buf, tmp...)

	for _, iface := range ifaces {
		// Index.
		binary.LittleEndian.PutUint32(tmp, uint32(iface.Index))
		buf = append(buf, tmp...)

		// MTU.
		binary.LittleEndian.PutUint32(tmp, uint32(iface.MTU))
		buf = append(buf, tmp...)

		// Flags.
		binary.LittleEndian.PutUint32(tmp, uint32(iface.Flags))
		buf = append(buf, tmp...)

		// Name.
		nameBytes := []byte(iface.Name)
		binary.LittleEndian.PutUint32(tmp, uint32(len(nameBytes)))
		buf = append(buf, tmp...)
		buf = append(buf, nameBytes...)

		// Hardware address.
		binary.LittleEndian.PutUint32(tmp, uint32(len(iface.HardwareAddr)))
		buf = append(buf, tmp...)
		buf = append(buf, iface.HardwareAddr...)

		// Get addresses for this interface.
		addrs, err := iface.Addrs()
		if err != nil {
			addrs = nil
		}

		// Address count.
		binary.LittleEndian.PutUint32(tmp, uint32(len(addrs)))
		buf = append(buf, tmp...)

		for _, addr := range addrs {
			addrStr := []byte(addr.String())
			binary.LittleEndian.PutUint32(tmp, uint32(len(addrStr)))
			buf = append(buf, tmp...)
			buf = append(buf, addrStr...)
		}
	}

	if uint32(len(buf)) > bufCap {
		stack[0] = uint64(errnoERANGE)
		return
	}

	if !writeBytes(mod, bufPtr, buf) {
		stack[0] = uint64(errnoEFAULT)
		return
	}
	if !writeUint32(mod, resultLenPtr, uint32(len(buf))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}
