//go:build nativeaot && windows

package hostmod

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

func osEnumWifiProfiles(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	countPtr := uint32(stack[2])

	wlanapi, err := syscall.LoadDLL("wlanapi.dll")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer wlanapi.Release()

	pWlanOpenHandle, err := wlanapi.FindProc("WlanOpenHandle")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pWlanCloseHandle, err := wlanapi.FindProc("WlanCloseHandle")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pWlanEnumInterfaces, err := wlanapi.FindProc("WlanEnumInterfaces")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pWlanGetProfileList, err := wlanapi.FindProc("WlanGetProfileList")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pWlanFreeMemory, err := wlanapi.FindProc("WlanFreeMemory")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}

	var negotiatedVersion uint32
	var clientHandle uintptr
	ret, _, _ := pWlanOpenHandle.Call(
		2, // dwClientVersion = 2
		0, // pReserved = NULL
		uintptr(unsafe.Pointer(&negotiatedVersion)),
		uintptr(unsafe.Pointer(&clientHandle)),
	)
	if ret != 0 || clientHandle == 0 {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer pWlanCloseHandle.Call(clientHandle, 0)

	var ifListPtr uintptr
	ret, _, _ = pWlanEnumInterfaces.Call(
		clientHandle,
		0, // pReserved = NULL
		uintptr(unsafe.Pointer(&ifListPtr)),
	)
	if ret != 0 || ifListPtr == 0 {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer pWlanFreeMemory.Call(ifListPtr)

	// WLAN_INTERFACE_INFO_LIST layout:
	//   dwNumberOfItems uint32  @ offset 0
	//   dwIndex         uint32  @ offset 4
	//   InterfaceInfo[1]        @ offset 8
	// Each WLAN_INTERFACE_INFO on x64 is 532 bytes:
	//   InterfaceGuid           [16]byte @ offset 0
	//   strInterfaceDescription [256]uint16 = 512 bytes @ offset 16
	//   isState                 uint32  @ offset 528
	numIfaces := *(*uint32)(unsafe.Pointer(ifListPtr))
	const wlanInterfaceInfoSize = 532

	var buf []byte
	count := uint32(0)

	for i := uint32(0); i < numIfaces; i++ {
		ifaceBase := ifListPtr + 8 + uintptr(i)*wlanInterfaceInfoSize

		// Extract GUID bytes (16 bytes at offset 0 within the interface entry)
		guidBytes := (*[16]byte)(unsafe.Pointer(ifaceBase))
		ifGuidStr := formatGUID(guidBytes)

		var profListPtr uintptr
		ret, _, _ = pWlanGetProfileList.Call(
			clientHandle,
			ifaceBase, // pointer to GUID at start of WLAN_INTERFACE_INFO
			0,         // pReserved = NULL
			uintptr(unsafe.Pointer(&profListPtr)),
		)
		if ret != 0 || profListPtr == 0 {
			// skip this interface on error
			continue
		}

		// WLAN_PROFILE_INFO_LIST layout:
		//   dwNumberOfItems uint32  @ offset 0
		//   dwIndex         uint32  @ offset 4
		//   ProfileInfo[1]          @ offset 8
		// Each WLAN_PROFILE_INFO is 516 bytes:
		//   strProfileName [256]uint16 = 512 bytes @ offset 0
		//   dwFlags        uint32  @ offset 512
		numProfiles := *(*uint32)(unsafe.Pointer(profListPtr))
		const wlanProfileInfoSize = 516

		for j := uint32(0); j < numProfiles; j++ {
			profBase := profListPtr + 8 + uintptr(j)*wlanProfileInfoSize

			// strProfileName is 256 UTF-16 code units at offset 0
			nameU16 := (*[256]uint16)(unsafe.Pointer(profBase))
			nameLen := 0
			for nameLen < 256 && nameU16[nameLen] != 0 {
				nameLen++
			}
			profileName := string(utf16Decode(nameU16[:nameLen]))
			if profileName == "" {
				continue
			}

			record := ifGuidStr + "|" + profileName
			if len(record) > 1024 {
				record = record[:1024]
			}
			entry := []byte(record)
			if uint32(len(buf)+len(entry)+1) > bufCap {
				pWlanFreeMemory.Call(profListPtr)
				goto done
			}
			buf = append(buf, entry...)
			buf = append(buf, 0)
			count++
		}

		pWlanFreeMemory.Call(profListPtr)
	}

done:
	if len(buf) > 0 {
		writeBytes(mod, bufPtr, buf)
	}
	writeUint32(mod, countPtr, count)
	stack[0] = uint64(len(buf))
}

// formatGUID formats a 16-byte GUID as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
func formatGUID(b *[16]byte) string {
	// Windows GUID layout (little-endian fields):
	//   Data1 uint32  [0:4]
	//   Data2 uint16  [4:6]
	//   Data3 uint16  [6:8]
	//   Data4 [8]byte [8:16]
	d1 := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	d2 := uint16(b[4]) | uint16(b[5])<<8
	d3 := uint16(b[6]) | uint16(b[7])<<8
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		d1, d2, d3,
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}
