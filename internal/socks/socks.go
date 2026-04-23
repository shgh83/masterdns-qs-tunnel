// Package socks provides a minimal SOCKS5 server-side handshake helper.
package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	version5        = 5
	cmdConnect      = 1
	atypIPv4        = 1
	atypDomain      = 3
	atypIPv6        = 4
	repSuccess      = 0
	repGeneralError = 1
	repCmdNotSupp   = 7
	repAtypNotSupp  = 8
)

// Handshake completes the SOCKS5 server-side greeting and request, negotiates
// no-authentication, and returns the requested target host and port.
// It does NOT send a reply; the caller must call SendSuccess or SendFailure
// once the outcome of the upstream connection is known.
func Handshake(conn net.Conn) (host string, port uint16, err error) {
	// Greeting: VER + NMETHODS + METHODS
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != version5 {
		err = fmt.Errorf("unsupported SOCKS version %d", header[0])
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err = io.ReadFull(conn, methods); err != nil {
		return
	}
	// Reply: choose NO AUTH (0x00)
	if _, err = conn.Write([]byte{version5, 0x00}); err != nil {
		return
	}

	// Request: VER + CMD + RSV + ATYP
	req := make([]byte, 4)
	if _, err = io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != version5 {
		err = fmt.Errorf("unsupported SOCKS version %d in request", req[0])
		return
	}
	if req[1] != cmdConnect {
		_, _ = conn.Write([]byte{version5, repCmdNotSupp, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		err = fmt.Errorf("unsupported SOCKS command %d (only CONNECT supported)", req[1])
		return
	}

	switch req[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err = io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		_, _ = conn.Write([]byte{version5, repAtypNotSupp, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		err = fmt.Errorf("unsupported SOCKS address type %d", req[3])
		return
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)
	return
}

// SendSuccess sends a SOCKS5 success reply (REP=0x00).
func SendSuccess(conn net.Conn) error {
	// VER=5, REP=0, RSV=0, ATYP=1(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := conn.Write([]byte{version5, repSuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// SendFailure sends a SOCKS5 general failure reply (REP=0x01).
func SendFailure(conn net.Conn) error {
	_, err := conn.Write([]byte{version5, repGeneralError, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
