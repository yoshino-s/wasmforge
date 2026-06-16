---
name: Bug report
about: Something built or ran differently than you expected
title: ""
labels: bug
---

## Summary

One or two sentences describing what went wrong.

## Reproduction

The exact `wasmforge` command (and any relevant env vars) that produced the
problem. If possible, point at a minimal guest project that reproduces.

```bash
# Example:
GOOS=windows GOARCH=amd64 ./wasmforge build --target windows ./my-broken-project
```

## Expected behavior

What you expected to see.

## Actual behavior

What actually happened. Include the error message, panic, or output diff.
Use a fenced code block.

## Environment

* `wasmforge version`:
* `go version`:
* Host OS + arch:
* Target `GOOS`/`GOARCH`:
* `.NET` SDK version (if applicable):
* Built via Docker, or natively?

## Additional context

Anything else that might help — links to similar issues, hunches about the
cause, screenshots if the failure is visible in a debugger.
