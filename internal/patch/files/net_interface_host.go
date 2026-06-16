// WasmForge replacement for net/interface_stub.go on wasip1.
// Provides real network interface enumeration via wasmforge host function.

//go:build wasip1

package net

import (
	"encoding/binary"
	"syscall"
)

//go:wasmimport env sys_netifs
//go:noescape
func wasmforge_net_interfaces(bufPtr *byte, bufCap uint32, resultLenPtr *uint32) uint32

// ifaceRecord holds the parsed fields of a single interface from the wire format.
type ifaceRecord struct {
	index   int
	mtu     int
	flags   Flags
	name    string
	hw      HardwareAddr
	addrs   []string // CIDR strings
	nextOff int      // offset after this record in the buffer
}

// parseIfaceRecord parses one interface record from data starting at offset.
// Returns the record and true on success, or a zero record and false if
// the data is truncated.
func parseIfaceRecord(data []byte, offset int) (ifaceRecord, bool) {
	end := len(data)

	if offset+12 > end {
		return ifaceRecord{}, false
	}
	idx := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	mtu := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	flags := Flags(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Name.
	if offset+4 > end {
		return ifaceRecord{}, false
	}
	nameLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if offset+nameLen > end {
		return ifaceRecord{}, false
	}
	name := string(data[offset : offset+nameLen])
	offset += nameLen

	// Hardware address.
	if offset+4 > end {
		return ifaceRecord{}, false
	}
	hwLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	var hw HardwareAddr
	if hwLen > 0 {
		if offset+hwLen > end {
			return ifaceRecord{}, false
		}
		hw = make(HardwareAddr, hwLen)
		copy(hw, data[offset:offset+hwLen])
		offset += hwLen
	}

	// Addresses.
	if offset+4 > end {
		return ifaceRecord{}, false
	}
	addrCount := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	var addrs []string
	for j := 0; j < addrCount; j++ {
		if offset+4 > end {
			return ifaceRecord{}, false
		}
		aLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if offset+aLen > end {
			return ifaceRecord{}, false
		}
		addrs = append(addrs, string(data[offset:offset+aLen]))
		offset += aLen
	}

	return ifaceRecord{
		index:   idx,
		mtu:     mtu,
		flags:   flags,
		name:    name,
		hw:      hw,
		addrs:   addrs,
		nextOff: offset,
	}, true
}

// fetchInterfaces calls the host function and returns the raw data.
func fetchInterfaces() ([]byte, error) {
	var buf [16384]byte
	var resultLen uint32
	errno := wasmforge_net_interfaces(&buf[0], uint32(len(buf)), &resultLen)
	if errno != 0 {
		return nil, syscall.Errno(errno)
	}
	out := make([]byte, resultLen)
	copy(out, buf[:resultLen])
	return out, nil
}

func interfaceTable(ifindex int) ([]Interface, error) {
	data, err := fetchInterfaces()
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, nil
	}

	count := binary.LittleEndian.Uint32(data[0:4])
	offset := 4

	ifaces := make([]Interface, 0, count)
	for i := uint32(0); i < count; i++ {
		rec, ok := parseIfaceRecord(data, offset)
		if !ok {
			break
		}
		offset = rec.nextOff

		if ifindex == 0 || ifindex == rec.index {
			ifaces = append(ifaces, Interface{
				Index:        rec.index,
				MTU:          rec.mtu,
				Name:         rec.name,
				HardwareAddr: rec.hw,
				Flags:        rec.flags,
			})
		}
	}

	return ifaces, nil
}

func interfaceAddrTable(ifi *Interface) ([]Addr, error) {
	data, err := fetchInterfaces()
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, nil
	}

	count := binary.LittleEndian.Uint32(data[0:4])
	offset := 4

	var addrs []Addr
	for i := uint32(0); i < count; i++ {
		rec, ok := parseIfaceRecord(data, offset)
		if !ok {
			break
		}
		offset = rec.nextOff

		if ifi == nil || ifi.Index == rec.index {
			for _, cidr := range rec.addrs {
				ip, ipnet, err := ParseCIDR(cidr)
				if err == nil {
					ipnet.IP = ip
					addrs = append(addrs, ipnet)
				}
			}
		}
	}

	return addrs, nil
}

func interfaceMulticastAddrTable(ifi *Interface) ([]Addr, error) {
	return nil, nil
}
