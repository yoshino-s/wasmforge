# Summary

What does this PR change? One short paragraph.

## Motivation

Why are we making this change? Link to the issue, the bug, the use case, or
the design discussion that prompted it. "Why" is more important than "what."

## Test plan

- [ ] `go vet ./...` is clean
- [ ] `go test ./...` passes
- [ ] If touching the build pipeline: I rebuilt `internal/build/build_assets.tar.gz` (`make generate`) and verified distribution-mode builds still work
- [ ] If touching `internal/hostmod/`: I ran the relevant `testdata/` programs end-to-end
- [ ] If touching guest libraries (`guest/win32`, `guest/darwin`, `guest/rawnet`): I ran the relevant `testdata/` programs end-to-end
- [ ] If touching docs: I previewed the markdown rendering

## Related issues

Link to any GitHub Issues, Discussions, or external references.

## Notes for reviewers

Anything reviewers should pay extra attention to — a specific subtle change,
a known follow-up, a tradeoff you'd like a second opinion on.
