/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"strings"
)

var (
	_ Bind = (*ParallelBind)(nil)
)

type ParallelBind struct {
	udp Bind
	tcp Bind
}

func NewParallelBind() Bind {
	return &ParallelBind{
		udp: NewStdNetBind(),
		tcp: NewTCPBind(),
	}
}

func (p *ParallelBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	udpFns, port, err := p.udp.Open(uport)
	if err != nil {
		return nil, 0, err
	}

	tcpFns, _, err := p.tcp.Open(port)
	if err != nil {
		// We don't want to fail if the TCP listener fails, so we just ignore the error.
	}

	return append(udpFns, tcpFns...), port, nil
}

func (p *ParallelBind) SetMark(mark uint32) error {
	err1 := p.udp.SetMark(mark)
	err2 := p.tcp.SetMark(mark)
	if err1 != nil {
		return err1
	}
	return err2
}

func (p *ParallelBind) Close() error {
	err1 := p.udp.Close()
	err2 := p.tcp.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (p *ParallelBind) Send(bufs [][]byte, endpoint Endpoint) error {
	ep, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	if ep.isTCP {
		return p.tcp.Send(bufs, endpoint)
	}
	return p.udp.Send(bufs, endpoint)
}

func (p *ParallelBind) ParseEndpoint(s string) (Endpoint, error) {
	if strings.HasPrefix(s, "tcp:") {
		return p.tcp.ParseEndpoint(s)
	}
	return p.udp.ParseEndpoint(s)
}

func (p *ParallelBind) BatchSize() int {
	// Since we can't know which bind will be used, we return the minimum.
	return 1
}
