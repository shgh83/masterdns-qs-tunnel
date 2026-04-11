//go:build !windows

package spoof

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

type RawUDPSender struct {
	fd int
}

func NewRawUDPSender() (*RawUDPSender, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &RawUDPSender{fd: fd}, nil
}

func (s *RawUDPSender) Close() error {
	if s == nil || s.fd <= 0 {
		return nil
	}
	return syscall.Close(s.fd)
}

func (s *RawUDPSender) SendUDP(payload []byte, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, ttl int) error {
	if !srcIP.Is4() || !dstIP.Is4() {
		return fmt.Errorf("raw spoof sender currently supports IPv4 only")
	}
	srcRaw := srcIP.As4()
	dstRaw := dstIP.As4()
	udpPacket := buildUDPPacket(payload, srcRaw, dstRaw, srcPort, dstPort)
	ipPacket := buildIPv4Packet(udpPacket, srcRaw, dstRaw, ttl)
	packet := append(ipPacket, udpPacket...)

	sockAddr := &syscall.SockaddrInet4{Port: int(dstPort), Addr: dstRaw}
	return syscall.Sendto(s.fd, packet, 0, sockAddr)
}

func buildUDPPacket(payload []byte, srcIP [4]byte, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	totalLen := 8 + len(payload)
	packet := make([]byte, totalLen)
	binary.BigEndian.PutUint16(packet[0:2], srcPort)
	binary.BigEndian.PutUint16(packet[2:4], dstPort)
	binary.BigEndian.PutUint16(packet[4:6], uint16(totalLen))
	copy(packet[8:], payload)

	pseudo := make([]byte, 12+len(packet))
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(totalLen))
	copy(pseudo[12:], packet)

	checksumValue := checksum(pseudo)
	if checksumValue == 0 {
		checksumValue = 0xffff
	}
	binary.BigEndian.PutUint16(packet[6:8], checksumValue)
	return packet
}

func buildIPv4Packet(payload []byte, srcIP [4]byte, dstIP [4]byte, ttl int) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[8] = byte(ttl)
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)+len(payload)))
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet))
	return packet
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
