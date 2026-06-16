//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

func win32LdapModify(ctx context.Context, mod api.Module,
	serverPtr, serverLen, port,
	dnPtr, dnLen, attrPtr, attrLen, valPtr, valLen, opCode,
	userPtr, userLen, domainPtr, domainLen,
	passwordPtr, passwordLen uint32) uint32 {
	return 0
}
