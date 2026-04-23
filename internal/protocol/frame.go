package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
)

type FrameKind byte

const (
	FrameData       FrameKind = 1 // legacy raw UDP relay data
	FrameInfo       FrameKind = 2 // client metadata (IP, port, spoof info)
	FrameConnect    FrameKind = 3 // open a proxied TCP stream
	FrameStreamData FrameKind = 4 // carry payload for a stream (both directions)
	FrameStreamFin  FrameKind = 5 // half-close a stream (both directions)
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
	case FrameData, FrameInfo, FrameConnect, FrameStreamData, FrameStreamFin:
		return kind, frame[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown frame kind %d", frame[0])
	}
}

// BuildConnectFrame builds a FrameConnect uplink frame:
// [kind:1][stream_id:4][host_len:1][host...][port:2]
func BuildConnectFrame(streamID uint32, host string, port uint16) []byte {
	frame := make([]byte, 1+4+1+len(host)+2)
	frame[0] = byte(FrameConnect)
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	frame[5] = byte(len(host))
	copy(frame[6:6+len(host)], host)
	binary.BigEndian.PutUint16(frame[6+len(host):], port)
	return frame
}

// ParseConnectPayload parses the payload portion (after the kind byte) of a FrameConnect.
func ParseConnectPayload(payload []byte) (streamID uint32, host string, port uint16, err error) {
	if len(payload) < 4+1+2 {
		return 0, "", 0, fmt.Errorf("connect payload too short")
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	hostLen := int(payload[4])
	if len(payload) < 4+1+hostLen+2 {
		return 0, "", 0, fmt.Errorf("connect payload truncated")
	}
	host = string(payload[5 : 5+hostLen])
	port = binary.BigEndian.Uint16(payload[5+hostLen : 5+hostLen+2])
	return streamID, host, port, nil
}

// BuildStreamDataFrame builds a FrameStreamData frame:
// [kind:1][stream_id:4][data...]
func BuildStreamDataFrame(streamID uint32, data []byte) []byte {
	frame := make([]byte, 1+4+len(data))
	frame[0] = byte(FrameStreamData)
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	copy(frame[5:], data)
	return frame
}

// ParseStreamDataPayload parses the payload portion (after the kind byte) of a FrameStreamData.
func ParseStreamDataPayload(payload []byte) (streamID uint32, data []byte, err error) {
	if len(payload) < 4 {
		return 0, nil, fmt.Errorf("stream data payload too short")
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	data = append([]byte(nil), payload[4:]...)
	return streamID, data, nil
}

// BuildStreamFinFrame builds a FrameStreamFin frame: [kind:1][stream_id:4]
func BuildStreamFinFrame(streamID uint32) []byte {
	frame := make([]byte, 1+4)
	frame[0] = byte(FrameStreamFin)
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	return frame
}

// ParseStreamFinPayload parses the payload portion (after the kind byte) of a FrameStreamFin.
func ParseStreamFinPayload(payload []byte) (uint32, error) {
	if len(payload) < 4 {
		return 0, fmt.Errorf("stream fin payload too short")
	}
	return binary.BigEndian.Uint32(payload[0:4]), nil
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
