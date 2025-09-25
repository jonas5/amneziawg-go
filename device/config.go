package device

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadConfig loads an INI-style configuration from the given file path and applies it to the device.
func (device *Device) LoadConfig(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var interfaceSettings = make(map[string]string)
	var peerSettings []map[string]string
	var currentSettings *map[string]string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "interface" {
				currentSettings = &interfaceSettings
			} else if section == "peer" {
				newPeer := make(map[string]string)
				peerSettings = append(peerSettings, newPeer)
				currentSettings = &newPeer
			} else {
				currentSettings = nil // Ignore unknown sections
			}
			continue
		}

		if currentSettings != nil {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				value := strings.TrimSpace(parts[1])
				(*currentSettings)[key] = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Apply interface settings
	for key, value := range interfaceSettings {
		if err := device.ApplyConfig(key, value, nil); err != nil {
			return fmt.Errorf("failed to apply interface setting '%s': %w", key, err)
		}
	}

	// Apply peer settings
	for _, settings := range peerSettings {
		pkStr, ok := settings["publickey"]
		if !ok {
			return errors.New("peer section is missing public key")
		}
		pk, err := NewNoisePublicKeyFromString(pkStr)
		if err != nil {
			return fmt.Errorf("invalid peer public key '%s': %w", pkStr, err)
		}

		peer, err := device.LookupOrCreatePeer(pk)
		if err != nil {
			return fmt.Errorf("failed to lookup/create peer with public key '%s': %w", pkStr, err)
		}

		for key, value := range settings {
			if key == "publickey" {
				continue
			}
			if err := device.ApplyConfig(key, value, peer); err != nil {
				return fmt.Errorf("failed to apply peer setting '%s' for peer %s: %w", key, pkStr, err)
			}
		}
	}

	return nil
}

func (device *Device) ApplyConfig(key, value string, peer *Peer) error {
	switch strings.ToLower(key) {
	case "privatekey", "private_key":
		sk, err := NewNoisePrivateKeyFromString(value)
		if err != nil {
			return err
		}
		return device.SetPrivateKey(sk)
	case "listenport", "listen_port":
		port, err := parsePort(value)
		if err != nil {
			return err
		}
		device.net.port = port
		return nil
	case "fwmark":
		mark, err := parseFwmark(value)
		if err != nil {
			return err
		}
		return device.BindSetMark(mark)
	case "presharedkey", "preshared_key":
		psk, err := NewNoisePresharedKeyFromString(value)
		if err != nil {
			return err
		}
		peer.handshake.mutex.Lock()
		peer.handshake.presharedKey = psk
		peer.handshake.mutex.Unlock()
		return nil
	case "endpoint":
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return err
		}
		peer.setEndpoint(endpoint)
		return nil
	case "persistentkeepalive", "persistent_keepalive_interval":
		interval, err := parsePersistentKeepalive(value)
		if err != nil {
			return err
		}
		peer.persistentKeepaliveInterval.Store(uint32(interval / time.Second))
		return nil
	case "allowedips", "allowed_ips":
		cidrs := strings.Split(value, ",")
		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return err
			}
			device.allowedips.Insert(prefix, peer)
		}
		return nil
	case "address", "postup", "postdown", "predown", "preup", "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4":
		// ignore these keys
		return nil
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}
}

func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(s, 10, 16)
	return uint16(port), err
}

func parseFwmark(s string) (uint32, error) {
	mark, err := strconv.ParseUint(s, 10, 32)
	return uint32(mark), err
}

func parsePersistentKeepalive(s string) (time.Duration, error) {
	interval, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return time.Duration(interval) * time.Second, nil
}

func NewNoisePrivateKeyFromString(s string) (NoisePrivateKey, error) {
	var key NoisePrivateKey
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(decoded) != NoisePrivateKeySize {
		return key, fmt.Errorf("invalid private key length")
	}
	copy(key[:], decoded)
	return key, nil
}

func NewNoisePublicKeyFromString(s string) (NoisePublicKey, error) {
	var key NoisePublicKey
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(decoded) != NoisePublicKeySize {
		return key, fmt.Errorf("invalid public key length")
	}
	copy(key[:], decoded)
	return key, nil
}

func NewNoisePresharedKeyFromString(s string) (NoisePresharedKey, error) {
	var key NoisePresharedKey
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(decoded) != NoisePresharedKeySize {
		return key, fmt.Errorf("invalid preshared key length")
	}
	copy(key[:], decoded)
	return key, nil
}
