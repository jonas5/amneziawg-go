package xray

import (
	"context"
	"io"
	"net"
	"strings"

	"github.com/amnezia-vpn/amnezia-xray-core/core"
	xraynet "github.com/amnezia-vpn/amnezia-xray-core/common/net"
	"github.com/amnezia-vpn/amnezia-xray-core/common/errors"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
)

func StartXray(config string) (core.Server, error) {
	c, err := core.LoadConfig("json", strings.NewReader(config))
	if err != nil {
		return nil, errors.New("failed to load config").Base(err)
	}

	server, err := core.New(c)
	if err != nil {
		return nil, errors.New("failed to create server").Base(err)
	}

	return server, nil
}

func Dial(ctx context.Context, instance core.Server, dest xraynet.Destination) (net.Conn, error) {
	return core.Dial(ctx, instance.(*core.Instance), dest)
}

func Receive(conn net.Conn, recv chan *conn.ReceivedPacket, ep conn.Endpoint, log *device.Logger) {
	for {
		buff := make([]byte, 1500)
		n, err := conn.Read(buff)
		if err != nil {
			if err != io.EOF {
				log.Errorf("xray receive error: %v", err)
			}
			return
		}
		newBuff := make([]byte, n)
		copy(newBuff, buff[:n])
		recv <- &conn.ReceivedPacket{data: newBuff, ep: ep}
	}
}
