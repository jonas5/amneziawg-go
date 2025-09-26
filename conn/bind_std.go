/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ Bind = (*StdNetBind)(nil)
)

// StdNetBind implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind struct {
	mu            sync.Mutex // protects all fields except as specified
	ipv4          *net.UDPConn
	ipv4PC        *ipv4.PacketConn // will be nil on non-Linux
	ipv4TxOffload bool
	ipv4RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool

	blackhole4 bool
}

func NewStdNetBind() Bind {
	return &StdNetBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
}

type StdNetEndpoint struct {
	netip.AddrPort
	src   []byte
	isTCP bool
}

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = &StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
		isTCP:    false,
	}, nil
}

func (e *StdNetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// See control_default,linux, etc for implementations of SrcIP and SrcIfidx.

func (e *StdNetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := listenConfig().ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

func (s *StdNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

again:
	port := int(uport)
	var v4conn *net.UDPConn
	var v4pc *ipv4.PacketConn

	v4conn, port, err = listenNet("udp4", port)
	if err != nil {
		if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			tries++
			goto again
		}
		return nil, 0, err
	}

	var fns []ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.ipv4PC = v4pc
		}
		fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload))
		s.ipv4 = v4conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}

func (s *StdNetBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

var (
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}
)

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func (s *StdNetBind) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (n int, err error) {
	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)
	var numMsgs int
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if rxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = br.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, err
			}
		}
	} else {
		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[i] = ep
	}
	return numMsgs, nil
}

func (s *StdNetBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	return 1
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.ipv4 != nil {
		err = s.ipv4.Close()
		s.ipv4 = nil
		s.ipv4PC = nil
	}
	s.blackhole4 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	return err
}

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload or peer MTU with protocol headers is greater than path MTU", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

func (s *StdNetBind) Send(bufs [][]byte, endpoint Endpoint) error {
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	offload := s.ipv4TxOffload
	br := batchWriter(s.ipv4PC)
	if endpoint.DstIP().Is6() {
		s.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)

	as4 := endpoint.DstIP().As4()
	copy(ua.IP, as4[:])
	ua.IP = ua.IP[:4]

	ua.Port = int(endpoint.(*StdNetEndpoint).Port())
	var (
		retried bool
		err     error
	)
retry:
	if offload {
		n := coalesceMessages(ua, endpoint.(*StdNetEndpoint), bufs, *msgs, setGSOSize)
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			s.ipv4TxOffload = false
			s.mu.Unlock()
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i]
			setSrcControl(&(*msgs)[i].OOB, endpoint.(*StdNetEndpoint))
		}
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (s *StdNetBind) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
	}
	return err
}

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8

	// This is a hard limit imposed by the kernel.
	udpSegmentMaxDatagrams = 64
)

type setGSOFunc func(control *[]byte, gsoSize uint16)

func coalesceMessages(addr *net.UDPAddr, ep *StdNetEndpoint, bufs [][]byte, msgs []ipv6.Message, setGSO setGSOFunc) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of bufs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buf := range bufs {
		if i > 0 {
			msgLen := len(buf)
			baseLenBefore := len(msgs[base].Buffers[0])
			freeBaseCap := cap(msgs[base].Buffers[0]) - baseLenBefore
			if msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], buf...)
				if i == len(bufs)-1 {
					setGSO(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSO(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buf)
		setSrcControl(&msgs[base].OOB, ep)
		msgs[base].Buffers[0] = buf
		msgs[base].Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

type getGSOFunc func(control []byte) (int, error)

func splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int, getGSO getGSOFunc) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = getGSO(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}
