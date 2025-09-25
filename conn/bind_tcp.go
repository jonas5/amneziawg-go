/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	_ Bind = (*TCPBind)(nil)
)

type TCPBind struct {
	mu            sync.Mutex
	lis4          net.Listener
	lis6          net.Listener
	conns         map[netip.AddrPort]net.Conn
	recv          chan *receiveResult
	accepts       sync.WaitGroup
	acceptDone    chan struct{}
}

func NewTCPBind() Bind {
	return &TCPBind{
		conns:         make(map[netip.AddrPort]net.Conn),
		recv:          make(chan *receiveResult, IdealBatchSize),
		acceptDone:    make(chan struct{}),
	}
}

func (t *TCPBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var err error
	var tries int

	if t.lis4 != nil || t.lis6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

again:
	port := int(uport)
	var lis4, lis6 net.Listener

	lis4, err = net.Listen("tcp4", ":"+strconv.Itoa(port))
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	lis6, err = net.Listen("tcp6", ":"+strconv.Itoa(port))
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		if lis4 != nil {
			lis4.Close()
		}
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		if lis4 != nil {
			lis4.Close()
		}
		return nil, 0, err
	}

	var fns []ReceiveFunc
	if lis4 != nil {
		t.lis4 = lis4
		t.accepts.Add(1)
		go t.accept(lis4)
	}
	if lis6 != nil {
		t.lis6 = lis6
		t.accepts.Add(1)
		go t.accept(lis6)
	}

	if t.lis4 != nil || t.lis6 != nil {
		fns = append(fns, t.makeReceive())
	}

	return fns, uint16(port), nil
}

func (t *TCPBind) Close() error {
	t.mu.Lock()
	if t.lis4 != nil {
		t.lis4.Close()
	}
	if t.lis6 != nil {
		t.lis6.Close()
	}
	close(t.acceptDone)
	t.mu.Unlock()

	t.accepts.Wait()

	t.mu.Lock()
	defer t.mu.Unlock()

	var errs []error
	for _, conn := range t.conns {
		errs = append(errs, conn.Close())
	}

	t.lis4 = nil
	t.lis6 = nil
	t.conns = make(map[netip.AddrPort]net.Conn)

	return errors.Join(errs...)
}

func (t *TCPBind) Send(bufs [][]byte, endpoint Endpoint) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ep, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}

	conn, ok := t.conns[ep.AddrPort]
	if !ok {
		return syscall.ENOTCONN
	}

	for _, buf := range bufs {
		// Simple framing: length-prefix each packet.
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, uint16(len(buf)))
		_, err := conn.Write(lenBuf)
		if err != nil {
			return err
		}
		_, err = conn.Write(buf)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *TCPBind) ParseEndpoint(s string) (Endpoint, error) {
	isTCP := strings.HasPrefix(s, "tcp:")
	if isTCP {
		s = s[4:]
	}
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
		isTCP:    true,
	}, nil
}

func (t *TCPBind) BatchSize() int {
	return 1
}

func (t *TCPBind) makeReceive() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		select {
		case res := <-t.recv:
			if res.err != nil {
				return 0, res.err
			}
			if len(res.buff) > len(bufs[0]) {
				// Drop oversized packet
				return 0, nil
			}
			n = copy(bufs[0], res.buff)
			sizes[0] = n
			eps[0] = res.ep
			return 1, nil
		default:
			return 0, nil
		}
	}
}

func (t *TCPBind) accept(l net.Listener) {
	defer t.accepts.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-t.acceptDone:
				return
			default:
			}
			select {
			case t.recv <- &receiveResult{err: err}:
			default:
			}
			return
		}

		addrPort, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}

		t.mu.Lock()
		t.conns[addrPort.AddrPort()] = conn
		t.mu.Unlock()

		t.accepts.Add(1)
		go t.receive(conn)
	}
}

func (t *TCPBind) receive(conn net.Conn) {
	defer t.accepts.Done()
	defer conn.Close()

	addrPort, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}

	for {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.recv <- &receiveResult{err: err}
			}
			t.mu.Lock()
			delete(t.conns, addrPort.AddrPort())
			t.mu.Unlock()
			return
		}
		pktLen := binary.LittleEndian.Uint16(lenBuf)

		if pktLen > 1500 {
			// Packet too large, drop and log
			// TODO: Add logging
			continue
		}

		buff := make([]byte, pktLen)
		_, err = io.ReadFull(conn, buff)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.recv <- &receiveResult{err: err}
			}
			t.mu.Lock()
			delete(t.conns, addrPort.AddrPort())
			t.mu.Unlock()
			return
		}

		ep := &StdNetEndpoint{
			AddrPort: addrPort.AddrPort(),
			isTCP:    true,
		}

		t.recv <- &receiveResult{buff: buff, ep: ep}
	}
}