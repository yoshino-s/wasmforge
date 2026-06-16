// Purego sysshim for WasmForge — routes through guest/darwin bridge.
//
// This file provides a wasip1-compatible implementation of github.com/ebitengine/purego
// by delegating native function calls through WasmForge's darwin host functions.

//go:build wasip1

package purego

import (
	"math"
	"reflect"
	"runtime"
	"sync"
	"unsafe"

	"github.com/praetorian-inc/wasmforge/guest/darwin"

	"github.com/ebitengine/purego/internal/strings"
)

// RTLD constants matching the real purego and macOS dlopen values.
const (
	RTLD_DEFAULT uintptr = 0 // special sentinel: search default symbol namespace
	RTLD_LAZY            = 0x1
	RTLD_NOW             = 0x2
	RTLD_LOCAL           = 0x4
	RTLD_GLOBAL          = 0x8
)

// CDecl marks a function as using the __cdecl calling convention when passed
// to NewCallback. Safe no-op on non-Windows platforms.
type CDecl struct{}

// Dlerror represents an error value returned from Dlopen, Dlsym, or Dlclose.
type Dlerror struct {
	s string
}

func (e Dlerror) Error() string {
	return e.s
}

// ---------- Handle mapping ----------
//
// purego's public API uses uintptr handles/addresses, while the darwin bridge
// uses int32 guest handles. We maintain a bidirectional map with synthetic
// uintptr keys starting at a high base to avoid collision with scalar values.

const handleBase uintptr = 0x8000_0000_0000_0000

type handleKind int

const (
	handleFramework handleKind = iota
	handleSymbol
)

type handleEntry struct {
	kind handleKind
	fw   darwin.Framework // valid when kind == handleFramework
	sym  darwin.Symbol    // valid when kind == handleSymbol
}

var handles struct {
	mu      sync.Mutex
	next    uintptr
	entries map[uintptr]*handleEntry
}

func init() {
	handles.next = handleBase
	handles.entries = make(map[uintptr]*handleEntry)
}

func allocHandle(e *handleEntry) uintptr {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	h := handles.next
	handles.next++
	handles.entries[h] = e
	return h
}

func getHandle(h uintptr) *handleEntry {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	return handles.entries[h]
}

func removeHandle(h uintptr) {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	delete(handles.entries, h)
}

// ---------- RTLD_DEFAULT support ----------
//
// When Dlsym is called with RTLD_DEFAULT, lazy-load libSystem.B.dylib.

var defaultLib struct {
	once sync.Once
	fw   darwin.Framework
	err  error
}

func getDefaultLib() (darwin.Framework, error) {
	defaultLib.once.Do(func() {
		defaultLib.fw, defaultLib.err = darwin.LoadFramework("/usr/lib/libSystem.B.dylib")
	})
	return defaultLib.fw, defaultLib.err
}

// ---------- dlfcn API ----------

// Dlopen loads a dynamic library. The path is passed through to darwin.LoadFramework
// which handles framework path expansion.
func Dlopen(path string, mode int) (uintptr, error) {
	fw, err := darwin.LoadFramework(path)
	if err != nil {
		return 0, Dlerror{s: "dlopen(" + path + "): " + err.Error()}
	}
	return allocHandle(&handleEntry{kind: handleFramework, fw: fw}), nil
}

// Dlsym looks up a symbol by name. handle must be a value returned by Dlopen
// or RTLD_DEFAULT.
func Dlsym(handle uintptr, name string) (uintptr, error) {
	var fw darwin.Framework
	if handle == RTLD_DEFAULT {
		var err error
		fw, err = getDefaultLib()
		if err != nil {
			return 0, Dlerror{s: "dlsym(RTLD_DEFAULT, " + name + "): " + err.Error()}
		}
	} else {
		entry := getHandle(handle)
		if entry == nil || entry.kind != handleFramework {
			return 0, Dlerror{s: "dlsym: invalid handle"}
		}
		fw = entry.fw
	}
	sym, err := fw.GetSymbol(name)
	if err != nil {
		return 0, Dlerror{s: "dlsym(" + name + "): " + err.Error()}
	}
	return allocHandle(&handleEntry{kind: handleSymbol, sym: sym}), nil
}

// Dlclose decrements the reference count on the handle. In the sysshim this
// simply removes the handle from the map.
func Dlclose(handle uintptr) error {
	removeHandle(handle)
	return nil
}

func loadSymbol(handle uintptr, name string) (uintptr, error) {
	return Dlsym(handle, name)
}

// ---------- SyscallN ----------

const maxArgs = 15

// SyscallN calls a native function via the darwin bridge. The fn argument must
// be a synthetic handle returned by Dlsym (not a raw host pointer).
// All args are passed without WASM pointer translation (callers manage their
// own pointers). Use syscallNMasked for selective translation.
//
//go:uintptrescapes
func SyscallN(fn uintptr, args ...uintptr) (r1, r2, err uintptr) {
	return syscallNMasked(fn, 0, args...)
}

// syscallNMasked calls a native function with a per-arg pointer translation mask.
// Bit i in ptrMask = 1 means arg i is a WASM pointer that needs host translation.
// Bit i = 0 means arg i is already a host value (ObjC ID, SEL, etc.).
func syscallNMasked(fn uintptr, ptrMask uint32, args ...uintptr) (r1, r2, err uintptr) {
	if fn == 0 {
		panic("purego: fn is nil")
	}
	if len(args) > maxArgs {
		panic("purego: too many arguments to SyscallN")
	}
	entry := getHandle(fn)
	if entry == nil || entry.kind != handleSymbol {
		panic("purego: SyscallN called with invalid handle")
	}
	if ptrMask == 0 {
		// No args need translation — use CallRaw for maximum safety.
		result, callErr := entry.sym.CallRaw(args...)
		if callErr != nil {
			return 0, 0, 1
		}
		return result, 0, 0
	}
	// Selective translation via CallMasked.
	result, callErr := entry.sym.CallMasked(ptrMask, args...)
	if callErr != nil {
		return 0, 0, 1
	}
	return result, 0, 0
}

// ---------- RegisterFunc / RegisterLibFunc ----------

// RegisterLibFunc is a wrapper around RegisterFunc that uses the C function
// returned from Dlsym(handle, name). It panics if the symbol is not found.
func RegisterLibFunc(fptr any, handle uintptr, name string) {
	sym, err := loadSymbol(handle, name)
	if err != nil {
		panic(err)
	}
	RegisterFunc(fptr, sym)
}

// RegisterFunc takes a pointer to a Go function variable and a C function
// handle (returned by Dlsym). It sets the function variable to a wrapper that
// calls the C function through the darwin bridge with appropriate type
// conversion.
func RegisterFunc(fptr any, cfn uintptr) {
	fn := reflect.ValueOf(fptr).Elem()
	ty := fn.Type()
	if ty.Kind() != reflect.Func {
		panic("purego: fptr must be a function pointer")
	}
	if ty.NumOut() > 1 {
		panic("purego: function can only return zero or one values")
	}
	if cfn == 0 {
		panic("purego: cfn is nil")
	}

	v := reflect.MakeFunc(ty, func(args []reflect.Value) []reflect.Value {
		uintArgs := make([]uintptr, 0, len(args))
		var ptrMask uint32
		var keepAlive []any

		// addArg processes a single value and appends to uintArgs.
		var addArg func(arg reflect.Value)
		addArg = func(arg reflect.Value) {
			argIdx := len(uintArgs)
			switch arg.Kind() {
			case reflect.String:
				ptr := strings.CString(arg.String())
				keepAlive = append(keepAlive, ptr)
				uintArgs = append(uintArgs, uintptr(unsafe.Pointer(ptr)))
				ptrMask |= 1 << uint(argIdx) // CString is in WASM memory → needs translation
			case reflect.Uintptr, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				uintArgs = append(uintArgs, uintptr(arg.Uint()))
				// NO mask bit — host value (ID, SEL, Class, etc.)
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				uintArgs = append(uintArgs, uintptr(arg.Int()))
			case reflect.Ptr, reflect.UnsafePointer:
				uintArgs = append(uintArgs, arg.Pointer())
				// Ptr could be Go heap (WASM) — mark for translation
				ptrMask |= 1 << uint(argIdx)
			case reflect.Slice:
				uintArgs = append(uintArgs, arg.Pointer())
				ptrMask |= 1 << uint(argIdx) // slice data in WASM memory
			case reflect.Bool:
				if arg.Bool() {
					uintArgs = append(uintArgs, 1)
				} else {
					uintArgs = append(uintArgs, 0)
				}
			case reflect.Float32:
				uintArgs = append(uintArgs, uintptr(math.Float32bits(float32(arg.Float()))))
			case reflect.Float64:
				uintArgs = append(uintArgs, uintptr(math.Float64bits(arg.Float())))
			case reflect.Func:
				uintArgs = append(uintArgs, NewCallback(arg.Interface()))
			case reflect.Interface:
				// Unwrap interface to get concrete value.
				if arg.IsNil() {
					uintArgs = append(uintArgs, 0)
				} else {
					addArg(arg.Elem())
				}
				return
			default:
				panic("purego: unsupported kind " + arg.Kind().String())
			}
		}

		for _, arg := range args {
			// Expand variadic []any slices (from ...any parameters).
			if variadic, ok := arg.Interface().([]any); ok {
				for _, x := range variadic {
					addArg(reflect.ValueOf(x))
				}
				continue
			}
			addArg(arg)
		}

		r1, _, _ := syscallNMasked(cfn, ptrMask, uintArgs...)

		runtime.KeepAlive(keepAlive)
		runtime.KeepAlive(args)

		if ty.NumOut() == 0 {
			return nil
		}

		outType := ty.Out(0)
		out := reflect.New(outType).Elem()
		switch outType.Kind() {
		case reflect.Uintptr, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			out.SetUint(uint64(r1))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			out.SetInt(int64(r1))
		case reflect.Bool:
			out.SetBool(byte(r1) != 0)
		case reflect.UnsafePointer:
			out.SetPointer(*(*unsafe.Pointer)(unsafe.Pointer(&r1)))
		case reflect.Ptr:
			// Heap-allocate r1 so the pointer outlives the closure frame.
			// NewAt(outType, &r1).Elem() reads the *T value FROM r1's memory,
			// yielding a *T whose underlying pointer IS r1 (the host address).
			heapR1 := new(uintptr)
			*heapR1 = r1
			out = reflect.NewAt(outType, unsafe.Pointer(heapR1)).Elem()
		case reflect.String:
			out.SetString(strings.GoString(r1))
		case reflect.Float32:
			out.SetFloat(float64(math.Float32frombits(uint32(r1))))
		case reflect.Float64:
			out.SetFloat(math.Float64frombits(uint64(r1)))
		case reflect.Func:
			out = reflect.New(outType)
			RegisterFunc(out.Interface(), r1)
		default:
			panic("purego: unsupported return kind: " + outType.Kind().String())
		}

		if len(args) > 0 {
			args[0] = out
			return args[:1]
		}
		return []reflect.Value{out}
	})
	fn.Set(v)
}

// ---------- NewCallback ----------

// NewCallback converts a Go function to a C function pointer conforming to
// the C calling convention. In the sysshim, this creates a host-side callback
// slot and spawns a goroutine that services invocations via the yield protocol.
//
// The returned uintptr is a synthetic handle that the host recognizes when
// passed as an argument to native APIs (e.g., class_addMethod's IMP parameter).
func NewCallback(fn any) uintptr {
	val := reflect.ValueOf(fn)
	if val.Kind() != reflect.Func {
		panic("purego: the type must be a function but was not")
	}
	if val.IsNil() {
		panic("purego: function must not be nil")
	}
	ty := val.Type()
	nargs := ty.NumIn()

	id, err := darwin.CreateCallback(nargs)
	if err != nil {
		panic("purego: NewCallback: " + err.Error())
	}
	addr, err := darwin.CallbackAddr(id)
	if err != nil {
		panic("purego: NewCallback: " + err.Error())
	}

	// Spawn a goroutine that services callback invocations.
	go func() {
		for {
			args, err := darwin.WaitCallback(id)
			if err != nil {
				return // slot freed or error
			}

			// Convert raw uintptr args to reflect.Values matching fn's signature.
			reflectArgs := make([]reflect.Value, ty.NumIn())
			for i := 0; i < ty.NumIn(); i++ {
				inType := ty.In(i)
				var arg uintptr
				if i < len(args) {
					arg = args[i]
				}
				switch inType.Kind() {
				case reflect.Uintptr:
					reflectArgs[i] = reflect.ValueOf(arg)
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					reflectArgs[i] = reflect.ValueOf(arg).Convert(inType)
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					reflectArgs[i] = reflect.ValueOf(int64(arg)).Convert(inType)
				case reflect.Ptr:
					reflectArgs[i] = reflect.NewAt(inType.Elem(), unsafe.Pointer(arg))
				case reflect.UnsafePointer:
					reflectArgs[i] = reflect.ValueOf(unsafe.Pointer(arg))
				case reflect.Bool:
					reflectArgs[i] = reflect.ValueOf(arg != 0)
				default:
					reflectArgs[i] = reflect.ValueOf(arg).Convert(inType)
				}
			}

			ret := val.Call(reflectArgs)

			var result uintptr
			if len(ret) > 0 {
				switch k := ret[0].Kind(); k {
				case reflect.Uint, reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8, reflect.Uintptr:
					result = uintptr(ret[0].Uint())
				case reflect.Int, reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8:
					result = uintptr(ret[0].Int())
				case reflect.Bool:
					if ret[0].Bool() {
						result = 1
					}
				case reflect.Ptr, reflect.UnsafePointer:
					result = ret[0].Pointer()
				}
			}

			_ = darwin.ReturnCallback(id, result)
		}
	}()

	return addr
}
