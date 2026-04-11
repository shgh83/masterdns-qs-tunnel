//go:build windows

package spoof

import (
	"fmt"
	"net/netip"
)

type RawUDPSender struct{}

func NewRawUDPSender() (*RawUDPSender, error) {
	return nil, fmt.Errorf("raw spoofed UDP is not supported on Windows builds")
}

func (s *RawUDPSender) Close() error {
	return nil
}

func (s *RawUDPSender) SendUDP(payload []byte, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, ttl int) error {
	return fmt.Errorf("raw spoofed UDP is not supported on Windows builds")
}
