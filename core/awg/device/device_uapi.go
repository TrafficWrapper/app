/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/ipc"
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

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
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

		params := device.awgParams()

		if params.junkCount != 0 {
			sendf("jc=%d", params.junkCount)
		}

		if params.junkMin != 0 {
			sendf("jmin=%d", params.junkMin)
		}

		if params.junkMax != 0 {
			sendf("jmax=%d", params.junkMax)
		}

		if params.initPadding != 0 {
			sendf("s1=%d", params.initPadding)
		}

		if params.responsePadding != 0 {
			sendf("s2=%d", params.responsePadding)
		}

		if params.cookiePadding != 0 {
			sendf("s3=%d", params.cookiePadding)
		}

		if params.transportPadding != 0 {
			sendf("s4=%d", params.transportPadding)
		}

		if params.initHeader != nil {
			sendf("h1=%s", params.initHeader.GenSpec())
		}

		if params.responseHeader != nil {
			sendf("h2=%s", params.responseHeader.GenSpec())
		}

		if params.cookieHeader != nil {
			sendf("h3=%s", params.cookieHeader.GenSpec())
		}

		if params.transportHeader != nil {
			sendf("h4=%s", params.transportHeader.GenSpec())
		}

		for i, ipacket := range params.ipackets {
			if ipacket != nil {
				sendf("i%d=%s", i+1, ipacket.Spec)
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

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
//
// The whole operation is read first and its device section (including every
// AmneziaWG parameter) is parsed and validated before anything is applied, so
// a rejected operation leaves the device untouched. The AWG parameters are
// then swapped in as one immutable snapshot.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	lines, err := readIpcSetLines(r)
	if err != nil {
		return err
	}

	staged, awgChanged, err := device.stageDeviceConfig(lines)
	if err != nil {
		return err
	}
	if awgChanged {
		device.log.Verbosef("UAPI: Updating AWG parameters")
		device.awg.Store(staged)
	}

	peer := new(ipcSetPeer)
	deviceConfig := true
	for _, line := range lines {
		key, value, _ := strings.Cut(line, "=")
		if key == "public_key" {
			deviceConfig = false
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
			if isAWGDeviceKey(key) {
				continue // already applied as part of the staged snapshot
			}
			err = device.handleDeviceLine(key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	peer.handlePostConfig()
	return nil
}

// maxIpcSetLines bounds one set operation; real configurations are a few
// dozen lines per peer.
const maxIpcSetLines = 1 << 16

// readIpcSetLines reads one set operation: lines up to a blank line or EOF.
func readIpcSetLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			return lines, nil
		}
		if !strings.Contains(line, "=") {
			return nil, ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}
		if len(lines) >= maxIpcSetLines {
			return nil, ipcErrorf(ipc.IpcErrorInvalid, "too many lines in UAPI set operation")
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return lines, nil
}

func isAWGDeviceKey(key string) bool {
	switch key {
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5":
		return true
	}
	return false
}

// stageDeviceConfig parses the device section of lines (everything before
// the first public_key) without touching the device. AWG keys are applied to
// a copy of the current parameters, which is validated as a whole; other
// device keys are only checked for syntax here and applied later.
func (device *Device) stageDeviceConfig(lines []string) (*awgParams, bool, error) {
	staged := device.awgParams().clone()
	changed := false
	for _, line := range lines {
		key, value, _ := strings.Cut(line, "=")
		if key == "public_key" {
			break
		}
		if isAWGDeviceKey(key) {
			if err := staged.set(key, value); err != nil {
				return nil, false, err
			}
			changed = true
			continue
		}
		if err := validateDeviceLine(key, value); err != nil {
			return nil, false, err
		}
	}
	if !changed {
		return nil, false, nil
	}
	if err := staged.validate(int(device.tun.mtu.Load())); err != nil {
		return nil, false, ipcErrorf(ipc.IpcErrorInvalid, "failed to merge with device: %w", err)
	}
	return staged, true, nil
}

func validateDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		if err := sk.FromMaybeZeroHex(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
	case "listen_port":
		if _, err := strconv.ParseUint(value, 10, 16); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}
	case "fwmark":
		if _, err := strconv.ParseUint(value, 10, 32); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}
	case "replace_peers":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
		}
	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}
	return nil
}

// set parses one AWG device key into p.
func (p *awgParams) set(key, value string) error {
	parseInt := func(name string, positive bool) (int, error) {
		v, err := strconv.Atoi(value)
		if err != nil {
			return 0, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", name, err)
		}
		if positive && v <= 0 {
			return 0, ipcErrorf(ipc.IpcErrorInvalid, "%s must be a positive value", name)
		}
		if !positive && v < 0 {
			return 0, ipcErrorf(ipc.IpcErrorInvalid, "%s must be non-negative", name)
		}
		return v, nil
	}
	parseHeader := func(name string) (*magicHeader, error) {
		header, err := newMagicHeader(value)
		if err != nil {
			return nil, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", name, err)
		}
		return header, nil
	}
	parseChain := func(name string) (*obfChain, error) {
		chain, err := newObfChain(value)
		if err != nil {
			return nil, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", name, err)
		}
		return chain, nil
	}
	var err error
	switch key {
	case "jc":
		p.junkCount, err = parseInt("jc", true)
	case "jmin":
		p.junkMin, err = parseInt("jmin", true)
	case "jmax":
		p.junkMax, err = parseInt("jmax", true)
	case "s1":
		p.initPadding, err = parseInt("s1", false)
	case "s2":
		p.responsePadding, err = parseInt("s2", false)
	case "s3":
		p.cookiePadding, err = parseInt("s3", false)
	case "s4":
		p.transportPadding, err = parseInt("s4", false)
	case "h1":
		p.initHeader, err = parseHeader("H1")
	case "h2":
		p.responseHeader, err = parseHeader("H2")
	case "h3":
		p.cookieHeader, err = parseHeader("H3")
	case "h4":
		p.transportHeader, err = parseHeader("H4")
	case "i1", "i2", "i3", "i4", "i5":
		idx := int(key[1] - '1')
		p.ipackets[idx], err = parseChain(strings.ToUpper(key))
	default:
		err = ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}
	return err
}

func (device *Device) handleDeviceLine(key, value string) error {
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

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
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

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
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
			err = device.IpcSetOperation(buffered.Reader)
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
