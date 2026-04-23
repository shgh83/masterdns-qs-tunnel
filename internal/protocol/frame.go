package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
)

type FrameKind byte

const (
	FrameData        FrameKind = 1
	FrameInfo        FrameKind = 2
	FrameConnect     FrameKind = 3
	FrameStreamData  FrameKind = 4
	FrameStreamClose FrameKind = 5
)

// DownlinkKind is the type tag for downlink (server→client) packets sent over UDP.
type DownlinkKind byte

const (
	DownlinkData       DownlinkKind = 1
	DownlinkClose      DownlinkKind = 2
	DownlinkConnected  DownlinkKind = 3
	DownlinkConnFailed DownlinkKind = 4
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
	case FrameData, FrameInfo, FrameConnect, FrameStreamData, FrameStreamClose:
		return kind, frame[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown frame kind %d", frame[0])
	}
}

// BuildConnectFrame builds a FrameConnect uplink frame.
// Layout: kind(1) + stream_id(4) + port(2) + host(variable).
func BuildConnectFrame(streamID uint32, host string, port uint16) []byte {
	buf := make([]byte, 1+4+2+len(host))
	buf[0] = byte(FrameConnect)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint16(buf[5:7], port)
	copy(buf[7:], host)
	return buf
}

// ParseConnectPayload parses the payload of a FrameConnect (after the kind byte).
func ParseConnectPayload(payload []byte) (streamID uint32, host string, port uint16, err error) {
	if len(payload) < 6 {
		return 0, "", 0, fmt.Errorf("connect payload too short")
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	port = binary.BigEndian.Uint16(payload[4:6])
	host = string(payload[6:])
	return
}

// BuildStreamDataFrame builds a FrameStreamData uplink frame.
// Layout: kind(1) + stream_id(4) + payload.
func BuildStreamDataFrame(streamID uint32, payload []byte) []byte {
	buf := make([]byte, 1+4+len(payload))
	buf[0] = byte(FrameStreamData)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	copy(buf[5:], payload)
	return buf
}

// ParseStreamDataPayload parses the payload of a FrameStreamData (after the kind byte).
func ParseStreamDataPayload(payload []byte) (streamID uint32, data []byte, err error) {
	if len(payload) < 4 {
		return 0, nil, fmt.Errorf("stream data payload too short")
	}
	streamID = binary.BigEndian.Uint32(payload[0:4])
	data = payload[4:]
	return
}

// BuildStreamCloseFrame builds a FrameStreamClose uplink frame.
// Layout: kind(1) + stream_id(4).
func BuildStreamCloseFrame(streamID uint32) []byte {
	buf := make([]byte, 1+4)
	buf[0] = byte(FrameStreamClose)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	return buf
}

// ParseStreamClosePayload parses the payload of a FrameStreamClose (after the kind byte).
func ParseStreamClosePayload(payload []byte) (streamID uint32, err error) {
	if len(payload) < 4 {
		return 0, fmt.Errorf("stream close payload too short")
	}
	return binary.BigEndian.Uint32(payload[0:4]), nil
}

// BuildDownlinkData builds a downlink data packet (server→client via UDP).
// Layout: kind(1) + stream_id(4) + payload.
func BuildDownlinkData(streamID uint32, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = byte(DownlinkData)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	copy(buf[5:], payload)
	return buf
}

// BuildDownlinkClose builds a downlink close packet.
func BuildDownlinkClose(streamID uint32) []byte {
	buf := make([]byte, 5)
	buf[0] = byte(DownlinkClose)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	return buf
}

// BuildDownlinkConnected builds a downlink connection-established packet.
func BuildDownlinkConnected(streamID uint32) []byte {
	buf := make([]byte, 5)
	buf[0] = byte(DownlinkConnected)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	return buf
}

// BuildDownlinkConnFailed builds a downlink connection-failed packet.
func BuildDownlinkConnFailed(streamID uint32) []byte {
	buf := make([]byte, 5)
	buf[0] = byte(DownlinkConnFailed)
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	return buf
}

// ParseDownlink parses a downlink packet received from the server.
func ParseDownlink(packet []byte) (kind DownlinkKind, streamID uint32, payload []byte, err error) {
	if len(packet) < 5 {
		return 0, 0, nil, fmt.Errorf("downlink packet too short: %d bytes", len(packet))
	}
	kind = DownlinkKind(packet[0])
	streamID = binary.BigEndian.Uint32(packet[1:5])
	payload = packet[5:]
	return
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
