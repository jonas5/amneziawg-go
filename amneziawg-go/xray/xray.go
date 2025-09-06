package xray

import (
	"context"
	"strings"

	"github.com/amnezia-vpn/amnezia-xray-core/core"
	"github.com/amnezia-vpn/amnezia-xray-core/common/net"
	"github.com/amnezia-vpn/amnezia-xray-core/common/errors"
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

func Dial(ctx context.Context, instance core.Server, dest net.Destination) (net.Conn, error) {
	return core.Dial(ctx, instance.(*core.Instance), dest)
}
