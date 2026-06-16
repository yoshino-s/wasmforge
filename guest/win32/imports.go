//go:build wasip1

package win32

// Host function imports for Win32 API operations.

// Generic DLL mechanism.

//go:wasmimport env mod_available
//go:noescape
func _win32_available() int32

//go:wasmimport env mod_load
//go:noescape
func _win32_load_library(namePtr *byte, nameLen int32, handlePtr *int32) int32

//go:wasmimport env mod_resolve
//go:noescape
func _win32_get_proc_address(libHandle int32, namePtr *byte, nameLen int32, procPtr *int32) int32

//go:wasmimport env mod_call
//go:noescape
func _win32_call(proc int32, nargs int32, argsPtr *uint32, retPtr *uint32) int32

//go:wasmimport env mod_free
//go:noescape
func _win32_free_library(handle int32) int32

// Registry.

//go:wasmimport env reg_open
//go:noescape
func _win32_reg_open_key(hkey int32, subkeyPtr *byte, subkeyLen int32, access uint32, handlePtr *int32) int32

//go:wasmimport env reg_close
//go:noescape
func _win32_reg_close_key(handle int32) int32

//go:wasmimport env reg_query
//go:noescape
func _win32_reg_query_value(handle int32, namePtr *byte, nameLen int32, typePtr *uint32, dataPtr *byte, dataLenPtr *uint32) int32

//go:wasmimport env reg_set
//go:noescape
func _win32_reg_set_value(handle int32, namePtr *byte, nameLen int32, vtype uint32, dataPtr *byte, dataLen uint32) int32

//go:wasmimport env reg_delete
//go:noescape
func _win32_reg_delete_value(handle int32, namePtr *byte, nameLen int32) int32

//go:wasmimport env reg_enum
//go:noescape
func _win32_reg_enum_key(handle int32, index uint32, namePtr *byte, nameLenPtr *uint32) int32

// Process/System.

//go:wasmimport env sys_compname
//go:noescape
func _win32_get_computer_name(bufPtr *byte, bufLenPtr *uint32) int32

//go:wasmimport env proc_create
//go:noescape
func _win32_create_process(cmdlinePtr *byte, cmdlineLen int32, flags uint32, pidPtr *uint32, handlePtr *int32) int32

//go:wasmimport env proc_open
//go:noescape
func _win32_open_process(access uint32, pid uint32, handlePtr *int32) int32

//go:wasmimport env proc_term
//go:noescape
func _win32_terminate_process(handle int32, exitCode uint32) int32

//go:wasmimport env mod_close
//go:noescape
func _win32_close_handle(handle int32) int32

// File.

//go:wasmimport env fs_create
//go:noescape
func _win32_create_file(pathPtr *byte, pathLen int32, access uint32, share uint32, creation uint32, flags uint32, handlePtr *int32) int32

//go:wasmimport env fs_read
//go:noescape
func _win32_read_file(handle int32, bufPtr *byte, bufLen uint32, nreadPtr *uint32) int32

//go:wasmimport env fs_write
//go:noescape
func _win32_write_file(handle int32, bufPtr *byte, bufLen uint32, nwrittenPtr *uint32) int32

//go:wasmimport env fs_getattr
//go:noescape
func _win32_get_file_attrs(pathPtr *byte, pathLen int32, attrsPtr *uint32) int32

//go:wasmimport env fs_setattr
//go:noescape
func _win32_set_file_attrs(pathPtr *byte, pathLen int32, attrs uint32) int32

// Security/Token.

//go:wasmimport env sec_opentoken
//go:noescape
func _win32_open_process_token(procHandle int32, access uint32, tokenPtr *int32) int32

//go:wasmimport env sec_tokeninfo
//go:noescape
func _win32_get_token_info(token int32, infoClass uint32, bufPtr *byte, bufLen uint32, neededPtr *uint32) int32

//go:wasmimport env svc_open
//go:noescape
func _win32_open_sc_manager(machinePtr *byte, machineLen int32, access uint32, handlePtr *int32) int32

//go:wasmimport env svc_status
//go:noescape
func _win32_query_service_status(svcHandle int32, statusPtr *byte) int32

//go:wasmimport env mod_invoke
//go:noescape
func _win32_syscalln(proc int32, nargs int32, argsPtr *byte, ret1Ptr *byte, ret2Ptr *byte, lastErrPtr *byte) int32

// Host memory management.

//go:wasmimport env mem_alloc
//go:noescape
func _win32_virtual_alloc(size uint32, allocType uint32, protect uint32, handlePtr *int32) int32

//go:wasmimport env mem_protect
//go:noescape
func _win32_virtual_protect(handle int32, newProtect uint32, oldProtectPtr *uint32) int32

//go:wasmimport env mem_free
//go:noescape
func _win32_virtual_free(handle int32) int32

//go:wasmimport env mem_write
//go:noescape
func _win32_hmem_write(handle int32, offset uint32, dataPtr *byte, dataLen uint32) int32

//go:wasmimport env mem_read
//go:noescape
func _win32_hmem_read(handle int32, offset uint32, bufPtr *byte, bufLen uint32) int32

//go:wasmimport env mem_write32
//go:noescape
func _win32_hmem_write32(handle int32, offset uint32, value uint32) int32

//go:wasmimport env mem_write64
//go:noescape
func _win32_hmem_write64(handle int32, offset uint32, valPtr *byte) int32

//go:wasmimport env mem_read32
//go:noescape
func _win32_hmem_read32(handle int32, offset uint32, valPtr *uint32) int32

//go:wasmimport env mem_read64
//go:noescape
func _win32_hmem_read64(handle int32, offset uint32, valPtr *byte) int32

//go:wasmimport env mem_addr
//go:noescape
func _win32_hmem_addr(handle int32, addrPtr *byte) int32

//go:wasmimport env mem_proc
//go:noescape
func _win32_proc_from_hmem(hmemHandle int32, offset uint32, procPtr *int32) int32

//go:wasmimport env mod_addr
//go:noescape
func _win32_proc_addr(procHandle int32, addrPtr *byte) int32

// Extension API callbacks.

//go:wasmimport env ext_getfunc
//go:noescape
func _win32_ext_get_func(funcId uint32, addrPtr *byte) int32

//go:wasmimport env ext_readout
//go:noescape
func _win32_ext_read_output(bufPtr *byte, bufLen uint32, actualLenPtr *uint32) int32

//go:wasmimport env ext_resetout
func _win32_ext_reset_output() int32
