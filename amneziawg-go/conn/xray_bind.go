/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/amnezia-vpn/amnezia-xray-core/core"
	xraynet "github.com/amnezia-vpn/amnezia-xray-core/common/net"
	"github.com/amnezia-vpn/amnezia-xray-core/common/protocol"
	"github.com/amnezia-vpn/amnezia-xray-core/transport/internet"
	"github.com/amnezia-vpn/amnezia-xray-core/proxy/freedom"
	"github.com/amnezia-vpn/amnezia-xray-core/common/serial"
)

type XrayBind struct {
	xrayInstance *core.Instance
	tcpWrapper   string
	conn         net.Conn
}

func NewXrayBind(tcpWrapper string) (Bind, error) {
	if tcpWrapper == "" {
		return nil, fmt.Errorf("TCP wrapper address cannot be empty")
	}

	host, portStr, err := net.SplitHostPort(tcpWrapper)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP wrapper address: %w", err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP wrapper port: %w", err)
	}

	config := &core.Config{
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DestinationOverride: &freedom.DestinationOverride{
						Server: &protocol.ServerEndpoint{
							Address: xraynet.NewIPOrDomain(xraynet.ParseAddress(host)),
							Port:    uint32(port),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&internet.ProxyConfig{}),
			},
		},
	}

	instance, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray instance: %w", err)
	}

	return &XrayBind{
		xrayInstance: instance,
		tcpWrapper:   tcpWrapper,
	}, nil
}

func (b *XrayBind) receiveFunc(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
	if len(packets) == 0 {
		return 0, nil
	}
	nRead, err := b.conn.Read(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = nRead
	// Since we're using a single TCP stream, we don't have a source endpoint.
	eps[0] = nil
	return 1, nil
}

func (b *XrayBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	if b.conn != nil {
		b.conn.Close()
	}

	dest, err := xraynet.ParseDestination("tcp:" + b.tcpWrapper)
	if err != nil {
		return nil, 0, err
	}

	conn, err := core.Dial(context.Background(), b.xrayInstance, dest)
	if err != nil {
		return nil, 0, err
	}
	b.conn = conn

	return []ReceiveFunc{b.receiveFunc}, 0, nil
}

func (b *XrayBind) Close() error {
	return b.xrayInstance.Close()
}

func (b *XrayBind) SetMark(mark uint32) error {
	// Not applicable to TCP wrapper
	return nil
}

func (b *XrayBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (b *XrayBind) Send(buffs [][]byte, endpoint Endpoint) error {
	if b.conn == nil {
		return fmt.Errorf("connection not open")
	}

	for _, buff := range buffs {
		_, err := b.conn.Write(buff)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *XrayBind) BatchSize() int {
	return 1
}
