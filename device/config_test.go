package device

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

type mockTun struct {
	tun.Device
}

func (m *mockTun) MTU() (int, error) {
	return 1420, nil
}

func (m *mockTun) BatchSize() int {
	return 1
}

func (m *mockTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, nil
}

func (m *mockTun) Events() <-chan tun.Event {
	return make(chan tun.Event)
}

func (m *mockTun) Close() error {
	return nil
}

type mockBind struct {
	conn.Bind
}

func (m *mockBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return nil, nil
}

func (m *mockBind) BatchSize() int {
	return 1
}

func (m *mockBind) SetMark(mark uint32) error {
	return nil
}

func (m *mockBind) Close() error {
	return nil
}

func (m *mockBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, port, nil
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file.
	file, err := ioutil.TempFile("", "config")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	// Write some config data to the file.
	configData := `
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ListenPort = 12345

[Peer]
PublicKey = fMkWAPl4o9+wIsiJ1bQ31/N4x2yDFaV2yNBsVns+c0Y=
AllowedIPs = 192.168.1.2/32
`
	if _, err := file.WriteString(configData); err != nil {
		t.Fatal(err)
	}
	file.Close()

	// Create a new device.
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(&mockTun{}, &mockBind{}, logger)
	if err := device.Up(); err != nil {
		t.Fatal(err)
	}

	// Load the config file.
	if err := device.LoadConfig(file.Name()); err != nil {
		t.Fatal(err)
	}

	// Verify that the config has been applied correctly.
	device.staticIdentity.RLock()
	if device.staticIdentity.privateKey.String() != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("private_key not set correctly: %s", device.staticIdentity.privateKey.String())
	}
	device.staticIdentity.RUnlock()
	if device.net.port != 12345 {
		t.Errorf("listen_port not set correctly")
	}
	device.peers.RLock()
	if len(device.peers.keyMap) != 1 {
		t.Errorf("expected 1 peer, got %d", len(device.peers.keyMap))
	}
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		if peer.handshake.remoteStatic.String() != "7cc91600f978a3dfb022c889d5b437d7f378c76c8315a576c8d06c567b3e7346" {
			t.Errorf("peer public key not set correctly")
		}
		peer.handshake.mutex.RUnlock()
	}
	device.peers.RUnlock()
}
