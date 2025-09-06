/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

var (
	_ Bind = (*TCPNetBind)(nil)
)

type TCPNetBind struct {
	mu         sync.Mutex
	listener   *net.TCPListener
	conns      map[string]net.Conn
	recvCh     chan receivedPacket
	isUp       bool
	isClosing  bool
}

type receivedPacket struct {
	packet []byte
	ep     Endpoint
}

func NewTCPNetBind() Bind {
	return &TCPNetBind{
		conns:  make(map[string]net.Conn),
		recvCh: make(chan receivedPacket, IdealBatchSize),
	}
}

func (s *TCPNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isUp {
		return nil, 0, ErrBindAlreadyOpen
	}

	addr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(int(uport)))
	if err != nil {
		return nil, 0, err
	}

	s.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, 0, err
	}

	s.isUp = true
	s.isClosing = false

	go s.acceptConns()

	return []ReceiveFunc{s.makeReceive()}, uint16(s.listener.Addr().(*net.TCPAddr).Port), nil
}

func (s *TCPNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.isClosing = true

	if s.listener != nil {
		s.listener.Close()
	}

	for _, conn := range s.conns {
		conn.Close()
	}

	s.isUp = false
	close(s.recvCh)
	return nil
}

func (s *TCPNetBind) Send(bufs [][]byte, ep Endpoint) error {
	s.mu.Lock()
	conn, ok := s.conns[ep.DstToString()]
	s.mu.Unlock()

	if !ok {
		var err error
		conn, err = net.Dial("tcp", ep.DstToString())
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.conns[ep.DstToString()] = conn
		s.mu.Unlock()
		go s.handleConn(conn)
	}

	for _, buf := range bufs {
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, uint16(len(buf)))
		_, err := conn.Write(append(lenBuf, buf...))
		if err != nil {
			conn.Close()
			s.mu.Lock()
			delete(s.conns, ep.DstToString())
			s.mu.Unlock()
			return err
		}
	}

	return nil
}

func (s *TCPNetBind) ParseEndpoint(e string) (Endpoint, error) {
	return parseEndpoint(e)
}

func (s *TCPNetBind) BatchSize() int {
	return IdealBatchSize
}

func (s *TCPNetBind) SetMark(mark uint32) error {
	// Not implemented for TCP
	return nil
}

func (s *TCPNetBind) acceptConns() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isClosing {
				return
			}
			continue
		}

		s.mu.Lock()
		s.conns[conn.RemoteAddr().String()] = conn
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

func (s *TCPNetBind) handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if !s.isClosing {
			}
			return
		}
		packetLen := binary.LittleEndian.Uint16(lenBuf)

		packet := make([]byte, packetLen)
		_, err = io.ReadFull(conn, packet)
		if err != nil {
			if !s.isClosing {
			}
			return
		}

		ep, err := s.ParseEndpoint(conn.RemoteAddr().String())
		if err != nil {
			continue
		}

		s.recvCh <- receivedPacket{packet: packet, ep: ep}
	}
}

func (s *TCPNetBind) makeReceive() ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		i := 0
		for ; i < IdealBatchSize; i++ {
			select {
			case pkt, ok := <-s.recvCh:
				if !ok {
					return i, net.ErrClosed
				}
				copy(packets[i], pkt.packet)
				sizes[i] = len(pkt.packet)
				eps[i] = pkt.ep
			default:
				return i, nil
			}
		}
		return i, nil
	}
}
