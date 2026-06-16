//go:build wasip1

package darwin

// Host function imports for Darwin/macOS framework operations.

//go:wasmimport env fw_available
//go:noescape
func _darwin_available() int32

//go:wasmimport env fw_load
//go:noescape
func _darwin_load(namePtr *byte, nameLen int32, handlePtr *int32) int32

//go:wasmimport env fw_sym
//go:noescape
func _darwin_get_symbol(libHandle int32, namePtr *byte, nameLen int32, symPtr *int32) int32

//go:wasmimport env fw_call
//go:noescape
func _darwin_call(symHandle int32, nargs int32, argsPtr *byte, retPtr *byte) int32

//go:wasmimport env fw_call_m
//go:noescape
func _darwin_call_masked(symHandle int32, nargs int32, argsPtr *byte, ptrMask int32, retPtr *byte) int32

//go:wasmimport env fw_call_raw
//go:noescape
func _darwin_call_raw(symHandle int32, nargs int32, argsPtr *byte, retPtr *byte) int32

//go:wasmimport env fw_mem_r
//go:noescape
func _darwin_mem_read(addrPtr *byte, offset uint32, bufPtr *byte, bufLen uint32) int32

//go:wasmimport env fw_mem_w
//go:noescape
func _darwin_mem_write(addrPtr *byte, offset uint32, dataPtr *byte, dataLen uint32) int32

// Callback infrastructure imports.

//go:wasmimport env fw_cb_create
//go:noescape
func _darwin_callback_create(nargs int32, idPtr *int32) int32

//go:wasmimport env fw_cb_addr
//go:noescape
func _darwin_callback_addr(id int32, addrPtr *byte) int32

//go:wasmimport env fw_cb_wait
//go:noescape
func _darwin_callback_wait(id int32, argsPtr *byte, argsCap int32, nargsPtr *int32) int32

//go:wasmimport env fw_cb_ret
//go:noescape
func _darwin_callback_return(id int32, result int64) int32

//go:wasmimport env fw_cb_free
//go:noescape
func _darwin_callback_free(id int32) int32

//go:wasmimport env fw_cstr_r
//go:noescape
func _darwin_read_cstring(hostAddrPtr *byte, bufPtr *byte, bufLen uint32, actualLenPtr *int32) int32

// Block construction imports.

//go:wasmimport env fw_blk_create
//go:noescape
func _darwin_block_create(cbID int32, sigPtr *byte, sigLen int32, blockIDPtr *int32) int32

//go:wasmimport env fw_blk_release
//go:noescape
func _darwin_block_release(blockID int32) int32

//go:wasmimport env fw_blk_addr
//go:noescape
func _darwin_block_addr(blockID int32, addrPtr *byte) int32
