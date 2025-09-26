package conn

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"
)

func TestParallelBind_OpenWithTCPPortInUse(t *testing.T) {
	// Capture log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)

	// Listen on a TCP port to reserve it.
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve TCP addr: %v", err)
	}
	tcpLis, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("Failed to listen on TCP port: %v", err)
	}
	defer tcpLis.Close()

	port := tcpLis.Addr().(*net.TCPAddr).Port

	// Now, try to open the parallel bind on the same port.
	// This will first open UDP (which should succeed) and then fail on TCP.
	pBind := NewParallelBind()
	_, _, err = pBind.Open(uint16(port))
	if err != nil {
		// We don't expect an error from Open itself, as it should be handled gracefully.
		t.Fatalf("pBind.Open() returned an unexpected error: %v", err)
	}
	defer pBind.Close()

	// Check if the log contains the warning about the TCP listener.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Warning: Failed to open TCP listener") {
		t.Errorf("Expected log to contain a warning about the TCP listener, but it didn't. Log: %s", logOutput)
	}
}