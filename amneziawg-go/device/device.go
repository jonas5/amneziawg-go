/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amnezia-xray-core/core"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device/awg"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/ratelimiter"
	"github.com/amnezia-vpn/amneziawg-go/rwcancel"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/xray"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		if device.isAWG() {
			if device.awg.Cfg.JunkPacketCount != 0 {
				sendf("jc=%d", device.awg.Cfg.JunkPacketCount)
			}
			if device.awg.Cfg.JunkPacketMinSize != 0 {
				sendf("jmin=%d", device.awg.Cfg.JunkPacketMinSize)
			}
			if device.awg.Cfg.JunkPacketMaxSize != 0 {
				sendf("jmax=%d", device.awg.Cfg.JunkPacketMaxSize)
			}
			if device.awg.Cfg.InitHeaderJunkSize != 0 {
				sendf("s1=%d", device.awg.Cfg.InitHeaderJunkSize)
			}
			if device.awg.Cfg.ResponseHeaderJunkSize != 0 {
				sendf("s2=%d", device.awg.Cfg.ResponseHeaderJunkSize)
			}
			if device.awg.Cfg.CookieReplyHeaderJunkSize != 0 {
				sendf("s3=%d", device.awg.Cfg.CookieReplyHeaderJunkSize)
			}
			if device.awg.Cfg.TransportHeaderJunkSize != 0 {
				sendf("s4=%d", device.awg.Cfg.TransportHeaderJunkSize)
			}
			for i, magicHeader := range device.awg.Cfg.MagicHeaders.Values {
				if magicHeader.Min > 4 {
					if magicHeader.Min == magicHeader.Max {
						sendf("h%d=%d", i+1, magicHeader.Min)
						continue
					}

					sendf("h%d=%d-%d", i+1, magicHeader.Min, magicHeader.Max)
				}
			}

			specialJunkIpcFields := device.awg.HandshakeHandler.SpecialJunk.IpcGetFields()
			for _, field := range specialJunkIpcFields {
				sendf("%s=%s", field.Key, field.Value)
			}
		}

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			sendf("protocol_version=1")
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()

			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			sendf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval.Load())

			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

type Version uint8

const (
	VersionDefault Version = iota
	VersionAwg
	VersionAwgSpecialHandshake
)

// TODO:
type AtomicVersion struct {
	value atomic.Uint32
}

func NewAtomicVersion(v Version) *AtomicVersion {
	av := &AtomicVersion{}
	av.Store(v)
	return av
}

func (av *AtomicVersion) Load() Version {
	return Version(av.value.Load())
}

func (av *AtomicVersion) Store(v Version) {
	av.value.Store(uint32(v))
}

func (av *AtomicVersion) CompareAndSwap(old, new Version) bool {
	return av.value.CompareAndSwap(uint32(old), uint32(new))
}

func (av *AtomicVersion) Swap(new Version) Version {
	return Version(av.value.Swap(uint32(new)))
}

type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to Up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; Up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to Device have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		netlinkCancel *rwcancel.RWCancel
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
		brokenRoaming bool
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
	}

	rate struct {
		underLoadUntil atomic.Int64
		limiter        ratelimiter.Ratelimiter
	}

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	pool struct {
		inboundElementsContainer  *WaitPool
		outboundElementsContainer *WaitPool
		messageBuffers            *WaitPool
		inboundElements           *WaitPool
		outboundElements          *WaitPool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	tun struct {
		device tun.Device
		mtu    atomic.Int32
	}

	ipcMutex sync.RWMutex
	closed   chan struct{}
	log      *Logger

	version    Version
	awg        awg.Protocol
	xray       *Xray
}

type Xray struct {
	server core.Server
	config string
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// Must hold device.peers.Lock()
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
}

// changeState attempts to change the device state to match want.
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	old := device.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		device.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	device.log.Verbosef(
		"Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) upLocked() error {
	if device.xray != nil && device.xray.config != "" {
		server, err := xray.StartXray(device.xray.config)
		if err != nil {
			device.log.Errorf("Failed to start Xray: %v", err)
			return err
		}
		device.xray.server = server
	}

	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Start()
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
	return nil
}

// downLocked attempts to bring the device down.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) downLocked() error {
	if device.xray != nil && device.xray.server != nil {
		device.xray.server.Close()
		device.xray.server = nil
	}
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

func (device *Device) IsUnderLoad() bool {
	// check if currently under load
	now := time.Now()
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device {
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.rate.limiter.Init()
	device.indexTable.Init()

	device.PopulatePools()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(cpus) // One for each RoutineHandshake
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1)
		go device.RoutineDecryption(i + 1)
		go device.RoutineHandshake(i + 1)
	}

	device.state.stopping.Add(1)      // RoutineReadFromTUN
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(uapi.NewScanner(uapiConf))
}

func (device *Device) IpcSetOperation(scanner *ipc.Scanner) error {
	var xrayConfig string
	var settings []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "xray_config=") {
			xrayConfig = strings.TrimPrefix(line, "xray_config=")
		} else {
			settings = append(settings, line)
		}
	}
	if xrayConfig != "" {
		device.xray = &Xray{config: xrayConfig}
	}

	return device.ipcSetInternal(bufio.NewScanner(strings.NewReader(strings.Join(settings, "\n"))))
}

import (
	"io"
	"net"
	"net/netip"
	"strconv"
)

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(bufio.NewScanner(buffered.Reader))
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(
					ipc.IpcErrorInvalid,
					"trailing character in UAPI get: %q",
					nextByte,
				)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}

func (device *Device) ipcSetInternal(scanner *bufio.Scanner) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	peer := new(ipcSetPeer)
	deviceConfig := true

	tempAwg := awg.Protocol{}
	tempAwg.Cfg.MagicHeaders.Values = make([]awg.MagicHeader, 4)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			err := device.handlePostConfig(&tempAwg)
			if err != nil {
				return err
			}
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(
				ipc.IpcErrorProtocol,
				"failed to parse line %q",
				line,
			)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(key, value, &tempAwg)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	err = device.handlePostConfig(&tempAwg)
	if err != nil {
		return err
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(
	peer *ipcSetPeer,
	value string,
) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handleDeviceLine(key, value string, tempAwg *awg.Protocol) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set replace_peers, invalid value: %v",
				value,
			)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	case "jc":
		junkPacketCount, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse junk_packet_count %w", err)
		}
		device.log.Verbosef("UAPI: Updating junk_packet_count")
		tempAwg.Cfg.JunkPacketCount = junkPacketCount
		tempAwg.Cfg.IsSet = true

	case "jmin":
		junkPacketMinSize, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse junk_packet_min_size %w", err)
		}
		device.log.Verbosef("UAPI: Updating junk_packet_min_size")
		tempAwg.Cfg.JunkPacketMinSize = junkPacketMinSize
		tempAwg.Cfg.IsSet = true

	case "jmax":
		junkPacketMaxSize, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse junk_packet_max_size %w", err)
		}
		device.log.Verbosef("UAPI: Updating junk_packet_max_size")
		tempAwg.Cfg.JunkPacketMaxSize = junkPacketMaxSize
		tempAwg.Cfg.IsSet = true

	case "s1":
		initPacketJunkSize, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse init_packet_junk_size %w", err)
		}
		device.log.Verbosef("UAPI: Updating init_packet_junk_size")
		tempAwg.Cfg.InitHeaderJunkSize = initPacketJunkSize
		tempAwg.Cfg.IsSet = true

	case "s2":
		responsePacketJunkSize, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse response_packet_junk_size %w", err)
		}
		device.log.Verbosef("UAPI: Updating response_packet_junk_size")
		tempAwg.Cfg.ResponseHeaderJunkSize = responsePacketJunkSize
		tempAwg.Cfg.IsSet = true

	case "s3":
		cookieReplyPacketJunkSize, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse cookie_reply_packet_junk_size %w", err)
		}
		device.log.Verbosef("UAPI: Updating cookie_reply_packet_junk_size")
		tempAwg.Cfg.CookieReplyHeaderJunkSize = cookieReplyPacketJunkSize
		tempAwg.Cfg.IsSet = true

	case "s4":
		transportPacketJunkSize, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "parse transport_packet_junk_size %w", err)
		}
		device.log.Verbosef("UAPI: Updating transport_packet_junk_size")
		tempAwg.Cfg.TransportHeaderJunkSize = transportPacketJunkSize
		tempAwg.Cfg.IsSet = true
	case "h1":
		initMagicHeader, err := awg.ParseMagicHeader(key, value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "uapi: %w", err)
		}

		tempAwg.Cfg.MagicHeaders.Values[0] = initMagicHeader
		tempAwg.Cfg.IsSet = true
	case "h2":
		responseMagicHeader, err := awg.ParseMagicHeader(key, value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "uapi: %w", err)
		}

		tempAwg.Cfg.MagicHeaders.Values[1] = responseMagicHeader
		tempAwg.Cfg.IsSet = true
	case "h3":
		cookieReplyMagicHeader, err := awg.ParseMagicHeader(key, value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "uapi: %w", err)
		}

		tempAwg.Cfg.MagicHeaders.Values[2] = cookieReplyMagicHeader
		tempAwg.Cfg.IsSet = true
	case "h4":
		transportMagicHeader, err := awg.ParseMagicHeader(key, value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "uapi: %w", err)
		}

		tempAwg.Cfg.MagicHeaders.Values[3] = transportMagicHeader
		tempAwg.Cfg.IsSet = true
	case "i1", "i2", "i3", "i4", "i5":
		if len(value) == 0 {
			device.log.Verbosef("UAPI: received empty %s", key)
			return nil
		}

		generators, err := awg.ParseTagJunkGenerator(key, value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid %s: %w", key, err)
		}
		device.log.Verbosef("UAPI: Updating %s", key)
		tempAwg.HandshakeHandler.SpecialJunk.AppendGenerator(generators)
		tempAwg.HandshakeHandler.IsSet = true
	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

func (device *Device) handlePeerLine(
	peer *ipcSetPeer,
	key, value string,
) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set update only, invalid value: %v",
				value,
			)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set persistent keepalive interval: %w",
				err,
			)
		}

		old := peer.persistentKeepaliveInterval.Swap(uint32(secs))

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to replace allowedips, invalid value: %v",
				value,
			)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

func (device *Device) Close() {
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	if device.isClosed() {
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Verbosef("Device closing")

	device.tun.device.Close()
	device.downLocked()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	device.RemoveAllPeers()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	device.state.stopping.Wait()

	device.rate.limiter.Close()

	device.resetProtocol()

	device.log.Verbosef("Device closed")
	close(device.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets
	if !device.isUp() {
		return nil
	}

	// bind to new port
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close()
		netc.port = 0
		return err
	}

	// set fwmark
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// start receiving routines
	device.net.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns)) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
	device.queue.handshake.wg.Add(len(recvFns))  // each RoutineReceiveIncoming goroutine writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}

func (device *Device) isAWG() bool {
	return device.version >= VersionAwg
}

func (device *Device) resetProtocol() {
	// restore default message type values
	MessageInitiationType = DefaultMessageInitiationType
	MessageResponseType = DefaultMessageResponseType
	MessageCookieReplyType = DefaultMessageCookieReplyType
	MessageTransportType = DefaultMessageTransportType
}

func (device *Device) handlePostConfig(tempAwg *awg.Protocol) error {
	if !tempAwg.Cfg.IsSet && !tempAwg.HandshakeHandler.IsSet {
		return nil
	}

	var errs []error

	isAwgOn := false
	device.awg.Mux.Lock()
	if tempAwg.Cfg.JunkPacketCount < 0 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketCount should be non negative",
		),
		)
	}
	device.awg.Cfg.JunkPacketCount = tempAwg.Cfg.JunkPacketCount
	if tempAwg.Cfg.JunkPacketCount != 0 {
		isAwgOn = true
	}

	device.awg.Cfg.JunkPacketMinSize = tempAwg.Cfg.JunkPacketMinSize
	if tempAwg.Cfg.JunkPacketMinSize != 0 {
		isAwgOn = true
	}

	if device.awg.Cfg.JunkPacketCount > 0 &&
		tempAwg.Cfg.JunkPacketMaxSize == tempAwg.Cfg.JunkPacketMinSize {

		tempAwg.Cfg.JunkPacketMaxSize++ // to make rand gen work
	}

	if tempAwg.Cfg.JunkPacketMaxSize >= MaxSegmentSize {
		device.awg.Cfg.JunkPacketMinSize = 0
		device.awg.Cfg.JunkPacketMaxSize = 1
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketMaxSize: %d; should be smaller than maxSegmentSize: %d",
			tempAwg.Cfg.JunkPacketMaxSize,
			MaxSegmentSize,
		))
	} else if tempAwg.Cfg.JunkPacketMaxSize < tempAwg.Cfg.JunkPacketMinSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"maxSize: %d; should be greater than minSize: %d",
			tempAwg.Cfg.JunkPacketMaxSize,
			tempAwg.Cfg.JunkPacketMinSize,
		))
	} else {
		device.awg.Cfg.JunkPacketMaxSize = tempAwg.Cfg.JunkPacketMaxSize
	}

	if tempAwg.Cfg.JunkPacketMaxSize != 0 {
		isAwgOn = true
	}

	magicHeaders := make([]awg.MagicHeader, 4)

	if len(tempAwg.Cfg.MagicHeaders.Values) != 4 {
		return ipcErrorf(
			ipc.IpcErrorInvalid,
			"magic headers should have 4 values; got: %d",
			len(tempAwg.Cfg.MagicHeaders.Values),
		)
	}

	if tempAwg.Cfg.MagicHeaders.Values[0].Min > 4 {
		isAwgOn = true
		device.log.Verbosef("UAPI: Updating init_packet_magic_header")
		magicHeaders[0] = tempAwg.Cfg.MagicHeaders.Values[0]

		MessageInitiationType = magicHeaders[0].Min
	} else {
		device.log.Verbosef("UAPI: Using default init type")
		MessageInitiationType = DefaultMessageInitiationType
		magicHeaders[0] = awg.NewMagicHeaderSameValue(DefaultMessageInitiationType)
	}

	if tempAwg.Cfg.MagicHeaders.Values[1].Min > 4 {
		isAwgOn = true

		device.log.Verbosef("UAPI: Updating response_packet_magic_header")
		magicHeaders[1] = tempAwg.Cfg.MagicHeaders.Values[1]
		MessageResponseType = magicHeaders[1].Min
	} else {
		device.log.Verbosef("UAPI: Using default response type")
		MessageResponseType = DefaultMessageResponseType
		magicHeaders[1] = awg.NewMagicHeaderSameValue(DefaultMessageResponseType)
	}

	if tempAwg.Cfg.MagicHeaders.Values[2].Min > 4 {
		isAwgOn = true

		device.log.Verbosef("UAPI: Updating underload_packet_magic_header")
		magicHeaders[2] = tempAwg.Cfg.MagicHeaders.Values[2]
		MessageCookieReplyType = magicHeaders[2].Min
	} else {
		device.log.Verbosef("UAPI: Using default underload type")
		MessageCookieReplyType = DefaultMessageCookieReplyType
		magicHeaders[2] = awg.NewMagicHeaderSameValue(DefaultMessageCookieReplyType)
	}

	if tempAwg.Cfg.MagicHeaders.Values[3].Min > 4 {
		isAwgOn = true

		device.log.Verbosef("UAPI: Updating transport_packet_magic_header")
		magicHeaders[3] = tempAwg.Cfg.MagicHeaders.Values[3]
		MessageTransportType = magicHeaders[3].Min
	} else {
		device.log.Verbosef("UAPI: Using default transport type")
		MessageTransportType = DefaultMessageTransportType
		magicHeaders[3] = awg.NewMagicHeaderSameValue(DefaultMessageTransportType)
	}

	var err error
	device.awg.Cfg.MagicHeaders, err = awg.NewMagicHeaders(magicHeaders)
	if err != nil {
		errs = append(errs, ipcErrorf(ipc.IpcErrorInvalid, "new magic headers: %w", err))
	}

	isSameHeaderMap := map[uint32]struct{}{
		MessageInitiationType:  {},
		MessageResponseType:    {},
		MessageCookieReplyType: {},
		MessageTransportType:   {},
	}

	// size will be different if same values
	if len(isSameHeaderMap) != 4 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`magic headers should differ; got: init:%d; recv:%d; unde:%d; tran:%d`,
			MessageInitiationType,
			MessageResponseType,
			MessageCookieReplyType,
			MessageTransportType,
		),
		)
	}

	newInitSize := MessageInitiationSize + tempAwg.Cfg.InitHeaderJunkSize

	if newInitSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`init header size(148) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.InitHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.InitHeaderJunkSize = tempAwg.Cfg.InitHeaderJunkSize
	}

	if tempAwg.Cfg.InitHeaderJunkSize != 0 {
		isAwgOn = true
	}

	newResponseSize := MessageResponseSize + tempAwg.Cfg.ResponseHeaderJunkSize

	if newResponseSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`response header size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.ResponseHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.ResponseHeaderJunkSize = tempAwg.Cfg.ResponseHeaderJunkSize
	}

	if tempAwg.Cfg.ResponseHeaderJunkSize != 0 {
		isAwgOn = true
	}

	newCookieSize := MessageCookieReplySize + tempAwg.Cfg.CookieReplyHeaderJunkSize

	if newCookieSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`cookie reply size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.CookieReplyHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.CookieReplyHeaderJunkSize = tempAwg.Cfg.CookieReplyHeaderJunkSize
	}

	if tempAwg.Cfg.CookieReplyHeaderJunkSize != 0 {
		isAwgOn = true
	}

	newTransportSize := MessageTransportSize + tempAwg.Cfg.TransportHeaderJunkSize

	if newTransportSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`transport size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.TransportHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.TransportHeaderJunkSize = tempAwg.Cfg.TransportHeaderJunkSize
	}

	if tempAwg.Cfg.TransportHeaderJunkSize != 0 {
		isAwgOn = true
	}

	isSameSizeMap := map[int]struct{}{
		newInitSize:      {},
		newResponseSize:  {},
		newCookieSize:    {},
		newTransportSize: {},
	}

	if len(isSameSizeMap) != 4 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`new sizes should differ; init: %d; response: %d; cookie: %d; trans: %d`,
			newInitSize,
			newResponseSize,
			newCookieSize,
			newTransportSize,
		),
		)
	} else {
		msgTypeToJunkSize = map[uint32]int{
			MessageInitiationType:  device.awg.Cfg.InitHeaderJunkSize,
			MessageResponseType:    device.awg.Cfg.ResponseHeaderJunkSize,
			MessageCookieReplyType: device.awg.Cfg.CookieReplyHeaderJunkSize,
			MessageTransportType:   device.awg.Cfg.TransportHeaderJunkSize,
		}

		packetSizeToMsgType = map[int]uint32{
			newInitSize:      MessageInitiationType,
			newResponseSize:  MessageResponseType,
			newCookieSize:    MessageCookieReplyType,
			newTransportSize: MessageTransportType,
		}
	}

	device.awg.IsOn.SetTo(isAwgOn)
	device.awg.JunkCreator = awg.NewJunkCreator(device.awg.Cfg)

	if tempAwg.HandshakeHandler.IsSet {
		if err := tempAwg.HandshakeHandler.Validate(); err != nil {
			errs = append(errs, ipcErrorf(
				ipc.IpcErrorInvalid, "handshake handler validate: %w", err))
		} else {
			device.awg.HandshakeHandler = tempAwg.HandshakeHandler
			device.awg.HandshakeHandler.SpecialJunk.DefaultJunkCount = tempAwg.Cfg.JunkPacketCount
			device.version = VersionAwgSpecialHandshake
		}
	} else {
		device.version = VersionAwg
	}

	device.awg.Mux.Unlock()

	return errors.Join(errs...)
}

func (device *Device) ProcessAWGPacket(size int, packet *[]byte, buffer *[MaxMessageSize]byte) (uint32, error) {
	// TODO:
	// if awg.WaitResponse.ShouldWait.IsSet() {
	// 	awg.WaitResponse.Channel <- struct{}{}
	// }

	expectedMsgType, isKnownSize := packetSizeToMsgType[size]
	if !isKnownSize {
		msgType, err := device.handleTransport(size, packet, buffer)

		if err != nil {
			return 0, fmt.Errorf("handle transport: %w", err)
		}

		return msgType, nil
	}

	junkSize := msgTypeToJunkSize[expectedMsgType]

	// transport size can align with other header types;
	// making sure we have the right actualMsgType
	actualMsgType, err := device.getMsgType(packet, junkSize)
	if err != nil {
		return 0, fmt.Errorf("get msg type: %w", err)
	}

	if actualMsgType == expectedMsgType {
		*packet = (*packet)[junkSize:]
		return actualMsgType, nil
	}

	device.log.Verbosef("awg: transport packet lined up with another msg type")

	msgType, err := device.handleTransport(size, packet, buffer)
	if err != nil {
		return 0, fmt.Errorf("handle transport: %w", err)
	}

	return msgType, nil
}

func (device *Device) getMsgType(packet *[]byte, junkSize int) (uint32, error) {
	msgTypeValue := binary.LittleEndian.Uint32((*packet)[junkSize : junkSize+4])
	msgType, err := device.awg.GetMagicHeaderMinFor(msgTypeValue)

	if err != nil {
		return 0, fmt.Errorf("get magic header min: %w", err)
	}

	return msgType, nil
}

func (device *Device) handleTransport(size int, packet *[]byte, buffer *[MaxMessageSize]byte) (uint32, error) {
	junkSize := device.awg.Cfg.TransportHeaderJunkSize

	msgType, err := device.getMsgType(packet, junkSize)
	if err != nil {
		return 0, fmt.Errorf("get msg type: %w", err)
	}

	if msgType != MessageTransportType {
		// probably a junk packet
		return 0, fmt.Errorf("Received message with unknown type: %d", msgType)
	}

	if junkSize > 0 {
		// remove junk from buffer by shifting the packet
		// this buffer is also used for decryption, so it needs to be corrected
		copy((*buffer)[:size], (*packet)[junkSize:])
		size -= junkSize
		// need to reinitialize packet as well
		(*packet) = (*packet)[:size]
	}

	return msgType, nil
}
