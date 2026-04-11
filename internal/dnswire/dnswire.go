package dnswire

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type Query struct {
	ID       uint16
	Flags    uint16
	QType    uint16
	Labels   [][]byte
	Question []byte
}

func EncodeDomain(domain string) ([]byte, error) {
	trimmed := strings.Trim(strings.TrimSpace(domain), ".")
	if trimmed == "" {
		return nil, fmt.Errorf("domain is empty")
	}
	parts := strings.Split(trimmed, ".")
	out := make([]byte, 0, len(trimmed)+2)
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("domain %q has empty label", domain)
		}
		if len(part) > 63 {
			return nil, fmt.Errorf("label %q too long", part)
		}
		out = append(out, byte(len(part)))
		out = append(out, []byte(strings.ToLower(part))...)
	}
	out = append(out, 0)
	return out, nil
}

func DomainLabels(domain string) ([][]byte, error) {
	trimmed := strings.Trim(strings.TrimSpace(domain), ".")
	if trimmed == "" {
		return nil, fmt.Errorf("domain is empty")
	}
	parts := strings.Split(trimmed, ".")
	out := make([][]byte, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("domain %q has empty label", domain)
		}
		if len(part) > 63 {
			return nil, fmt.Errorf("label %q too long", part)
		}
		out = append(out, []byte(strings.ToLower(part)))
	}
	return out, nil
}

func InsertLabels(data []byte, maxLabelLen int) ([]byte, error) {
	if maxLabelLen <= 0 || maxLabelLen > 63 {
		return nil, fmt.Errorf("max label len must be 1..63")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot insert empty label set")
	}
	out := make([]byte, 0, len(data)+(len(data)/maxLabelLen)+1)
	for start := 0; start < len(data); start += maxLabelLen {
		end := start + maxLabelLen
		if end > len(data) {
			end = len(data)
		}
		segment := data[start:end]
		out = append(out, byte(len(segment)))
		out = append(out, segment...)
	}
	return out, nil
}

func BuildQuery(qnameEncoded []byte, queryID uint16, qtype uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], queryID)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)

	question := make([]byte, len(qnameEncoded)+4)
	copy(question, qnameEncoded)
	binary.BigEndian.PutUint16(question[len(qnameEncoded):len(qnameEncoded)+2], qtype)
	binary.BigEndian.PutUint16(question[len(qnameEncoded)+2:], 1)
	return append(header, question...)
}

func ParseQuery(packet []byte) (Query, error) {
	if len(packet) < 17 {
		return Query{}, fmt.Errorf("packet too short")
	}

	query := Query{
		ID:    binary.BigEndian.Uint16(packet[0:2]),
		Flags: binary.BigEndian.Uint16(packet[2:4]),
	}
	qdCount := binary.BigEndian.Uint16(packet[4:6])
	if qdCount != 1 {
		return Query{}, fmt.Errorf("expected exactly one question")
	}
	if query.Flags&0x8000 != 0 {
		return Query{}, fmt.Errorf("packet is not a query")
	}

	offset := 12
	labels := make([][]byte, 0, 8)
	for {
		if offset >= len(packet) {
			return Query{}, fmt.Errorf("truncated qname")
		}
		labelLen := int(packet[offset])
		offset++
		if labelLen == 0 {
			break
		}
		if labelLen > 63 {
			return Query{}, fmt.Errorf("invalid label len %d", labelLen)
		}
		if offset+labelLen > len(packet) {
			return Query{}, fmt.Errorf("truncated label")
		}
		label := make([]byte, labelLen)
		copy(label, packet[offset:offset+labelLen])
		for i := range label {
			if label[i] >= 'A' && label[i] <= 'Z' {
				label[i] += 'a' - 'A'
			}
		}
		labels = append(labels, label)
		offset += labelLen
	}

	if offset+4 > len(packet) {
		return Query{}, fmt.Errorf("truncated question trailer")
	}
	query.QType = binary.BigEndian.Uint16(packet[offset : offset+2])
	qclass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	if qclass != 1 {
		return Query{}, fmt.Errorf("unsupported qclass %d", qclass)
	}
	query.Labels = labels
	query.Question = append([]byte(nil), packet[12:offset+4]...)
	return query, nil
}

func CreateEmptyNoErrorResponse(id uint16, flags uint16, question []byte) []byte {
	var rcodeBit uint16
	if (flags & 0x7800) != 0 {
		rcodeBit = 1
	}
	responseFlags := uint16(0x8400) | (flags & 0x7910) | rcodeBit
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], responseFlags)
	binary.BigEndian.PutUint16(header[4:6], 1)
	return append(header, question...)
}
