;; Minimal traffic encoder matching Sliver's expected ABI.
;; Exports: encode, decode, malloc, free
;; Implements XOR-0x41 encoding (self-inverse, so decode = encode).
(module
  (memory (export "memory") 1)  ;; 1 page = 64KB

  ;; Simple bump allocator. Global tracks next free offset.
  (global $heap_ptr (mut i32) (i32.const 1024))  ;; start after first 1KB

  (func $malloc (export "malloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap_ptr))
    (global.set $heap_ptr (i32.add (global.get $heap_ptr) (local.get $size)))
    (local.get $ptr)
  )

  (func $free (export "free") (param $ptr i32)
    ;; no-op
  )

  ;; encode: XOR each byte with 0x41, return (ptr << 32) | size as i64
  (func $encode (export "encode") (param $ptr i32) (param $size i32) (result i64)
    (local $out_ptr i32)
    (local $i i32)
    ;; Allocate output buffer
    (local.set $out_ptr (call $malloc (local.get $size)))
    ;; XOR loop
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (local.get $size)))
        (i32.store8
          (i32.add (local.get $out_ptr) (local.get $i))
          (i32.xor
            (i32.load8_u (i32.add (local.get $ptr) (local.get $i)))
            (i32.const 0x41)
          )
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
    ;; Return packed result: (out_ptr << 32) | size
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $out_ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $size))
    )
  )

  ;; decode is the same as encode (XOR is self-inverse)
  (func $decode (export "decode") (param $ptr i32) (param $size i32) (result i64)
    (call $encode (local.get $ptr) (local.get $size))
  )
)
