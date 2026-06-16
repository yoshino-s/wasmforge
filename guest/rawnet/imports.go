//go:build wasip1

package rawnet

// Host function imports for raw socket operations.

//go:wasmimport env fd_raw_open
//go:noescape
func raw_sock_open(domain, protocol int32, fd *int32) int32

//go:wasmimport env fd_raw_send
//go:noescape
func raw_sock_send(fd int32, buf *byte, bufLen int32, flags int32, dest *byte, destLen int32, nsent *int32) int32

//go:wasmimport env fd_raw_recv
//go:noescape
func raw_sock_recv(fd int32, buf *byte, bufLen int32, flags int32, src *byte, srcCap int32, srcLen *int32, nrecv *int32) int32

//go:wasmimport env fd_close2
//go:noescape
func raw_sock_close(fd int32) int32
