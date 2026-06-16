# LDAP Bridge Test Harness

Exercises `WfLdapSearch` / `WfLdapSearchExt` against a GOAD DC at
`dc01.sevenkingdoms.local`. Use the `win11-domainadmin` persona so the
caller is already domain-authenticated.

## Triage finding (2026-06-03)

```
WfLdapSearch(anon) rc=0x00000000 bytes_written=0
WfLdapSearchExt(bind) rc=0x00000000 bytes_written=0
```

Both wrappers return cleanly (no AV, no crash) but produce zero output
bytes — same observable failure mode as Certify's `enum-cas` /
`enum-templates` / `enum-pkiobjects`. The host-side
`internal/hostmod/nativeaot_ldap_windows.go` implementation is suspect:
either the bind succeeds but search returns no entries, or the entries
are produced and dropped on the way back to wasm. Next step: add
`fmt.Fprintf(os.Stderr, ...)` to the host LDAP path and re-run the
harness to see exactly where bytes are lost.

## Build
Same pattern as crypto-harness/.
