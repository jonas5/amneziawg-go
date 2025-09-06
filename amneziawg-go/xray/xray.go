package xray

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/amnezia-vpn/amnezia-xray-core/core"
	"github.com/amnezia-vpn/amnezia-xray-core/common/errors"
	xraynet "github.com/amnezia-vpn/amnezia-xray-core/common/net"
	"github.com/amnezia-vpn/amneziawg-go/logger"
)

type PacketReceiver interface {
	ReceivePacket(data []byte, ep any)
}

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

func Receive(conn net.Conn, receiver PacketReceiver, ep any, log *logger.Logger) {
	var lenbuf [2]byte
	for {
		_, err := io.ReadFull(conn, lenbuf[:])
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Errorf("xray receive error (reading length): %v", err)
			}
			return
		}

		length := binary.BigEndian.Uint16(lenbuf[:])
		packetBuf := make([]byte, length)

		_, err = io.ReadFull(conn, packetBuf)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Errorf("xray receive error (reading packet): %v", err)
			}
			return
		}

		receiver.ReceivePacket(packetBuf, ep)
	}
}
