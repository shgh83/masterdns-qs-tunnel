package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
)

type FrameKind byte

const (
	FrameData FrameKind = 1
	FrameInfo FrameKind = 2
)

type InfoFrame struct {
	ClientIP   netip.Addr
	ClientPort uint16
	SpoofIP    netip.Addr
	SpoofPort  uint16
}

func BuildDataFrame(payload []byte) []byte {
	frame := make([]byte, 1+len(payload))
	frame[0] = byte(FrameData)
	copy(frame[1:], payload)
	return frame
}

func BuildInfoFrame(info InfoFrame, secret string) ([]byte, error) {
	body, err := info.MarshalBinary()
	if err != nil {
		return nil, err
	}
	mask := sha256.Sum256([]byte(secret))
	body = xorMask(body, mask[:])
	frame := make([]byte, 1+len(body))
	frame[0] = byte(FrameInfo)
	copy(frame[1:], body)
	return frame, nil
}

func ParseFrame(frame []byte) (FrameKind, []byte, error) {
	if len(frame) == 0 {
		return 0, nil, fmt.Errorf("frame is empty")
	}
	kind := FrameKind(frame[0])
	switch kind {
	case FrameData, FrameInfo:
		return kind, frame[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown frame kind %d", frame[0])
	}
}

func ParseInfoFrame(payload []byte, secret string) (InfoFrame, error) {
	if len(payload) != 12 {
		return InfoFrame{}, fmt.Errorf("info frame must be 12 bytes after decryption, got %d", len(payload))
	}
	mask := sha256.Sum256([]byte(secret))
	decoded := xorMask(payload, mask[:])
	var clientRaw [4]byte
	var spoofRaw [4]byte
	copy(clientRaw[:], decoded[0:4])
	copy(spoofRaw[:], decoded[6:10])
	return InfoFrame{
		ClientIP:   netip.AddrFrom4(clientRaw),
		ClientPort: binary.BigEndian.Uint16(decoded[4:6]),
		SpoofIP:    netip.AddrFrom4(spoofRaw),
		SpoofPort:  binary.BigEndian.Uint16(decoded[10:12]),
	}, nil
}

func (i InfoFrame) MarshalBinary() ([]byte, error) {
	if !i.ClientIP.Is4() || !i.SpoofIP.Is4() {
		return nil, fmt.Errorf("only IPv4 info frames are supported")
	}
	clientRaw := i.ClientIP.As4()
	spoofRaw := i.SpoofIP.As4()
	out := make([]byte, 12)
	copy(out[0:4], clientRaw[:])
	binary.BigEndian.PutUint16(out[4:6], i.ClientPort)
	copy(out[6:10], spoofRaw[:])
	binary.BigEndian.PutUint16(out[10:12], i.SpoofPort)
	return out, nil
}

func xorMask(src []byte, mask []byte) []byte {
	dst := make([]byte, len(src))
	for i := range src {
		dst[i] = src[i] ^ mask[i%len(mask)]
	}
	return dst
}
