package internet_test

import (
	"context"
	"testing"

	"github.com/amnezia-vpn/amnezia-xray-core/common"
	"github.com/amnezia-vpn/amnezia-xray-core/common/net"
	"github.com/amnezia-vpn/amnezia-xray-core/testing/servers/tcp"
	. "github.com/amnezia-vpn/amnezia-xray-core/transport/internet"
	"github.com/google/go-cmp/cmp"
)

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}
