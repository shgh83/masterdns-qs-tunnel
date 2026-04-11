package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/blackestwhite/masterdns-qs-tunnel/internal/base36x"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/dnswire"
)

const (
	maxFragments       = 255
	uplinkHeaderLength = 6
)

type DomainMatcher struct {
	Name   string
	Labels [][]byte
}

type DomainPlan struct {
	DomainMatcher
	Encoded         []byte
	MaxEncodedChars int
	MaxPayloadBytes int
}

type Chunk struct {
	ClientID      string
	Offset        uint64
	FragmentIndex int
	Last          bool
	EncodedData   []byte
}

func PrepareMatchers(domains []string) ([]DomainMatcher, error) {
	out := make([]DomainMatcher, 0, len(domains))
	for _, domain := range domains {
		labels, err := dnswire.DomainLabels(domain)
		if err != nil {
			return nil, err
		}
		out = append(out, DomainMatcher{
			Name:   strings.ToLower(strings.Trim(domain, ".")),
			Labels: labels,
		})
	}
	return out, nil
}

func PrepareDomainPlans(domains []string, maxQNameLen, maxLabelLen, offsetWidth, clientIDLen int) ([]DomainPlan, error) {
	_ = offsetWidth
	matchers, err := PrepareMatchers(domains)
	if err != nil {
		return nil, err
	}
	out := make([]DomainPlan, 0, len(matchers))
	for _, matcher := range matchers {
		encoded, err := dnswire.EncodeDomain(matcher.Name)
		if err != nil {
			return nil, err
		}
		maxEncodedChars, err := calculateMaxEncodedChars(maxQNameLen, len(encoded), maxLabelLen)
		if err != nil {
			return nil, fmt.Errorf("domain %s leaves no room for data", matcher.Name)
		}
		maxRawBytes := calculateMaxRawBytes(maxEncodedChars)
		maxPayloadBytes := maxRawBytes - 1 - clientIDLen - uplinkHeaderLength
		if maxPayloadBytes <= 0 {
			return nil, fmt.Errorf("domain %s leaves no room for payload chunks", matcher.Name)
		}
		out = append(out, DomainPlan{
			DomainMatcher:   matcher,
			Encoded:         encoded,
			MaxEncodedChars: maxEncodedChars,
			MaxPayloadBytes: maxPayloadBytes,
		})
	}
	return out, nil
}

func MatchDomain(labels [][]byte, matchers []DomainMatcher) (DomainMatcher, int, bool) {
	for _, matcher := range matchers {
		if len(labels) < len(matcher.Labels) {
			continue
		}
		offset := len(labels) - len(matcher.Labels)
		ok := true
		for i := range matcher.Labels {
			if string(labels[offset+i]) != string(matcher.Labels[i]) {
				ok = false
				break
			}
		}
		if ok {
			return matcher, len(matcher.Labels), true
		}
	}
	return DomainMatcher{}, 0, false
}

func BuildQNames(frame []byte, offset uint64, clientID string, plans []DomainPlan, startIndex, maxLabelLen, offsetWidth int) ([][]byte, int, error) {
	if len(plans) == 0 {
		return nil, startIndex, fmt.Errorf("no domain plans configured")
	}
	_ = offsetWidth

	plan := plans[startIndex%len(plans)]
	if plan.MaxPayloadBytes <= 0 {
		return nil, startIndex, fmt.Errorf("selected domain plan has no payload capacity")
	}

	totalFragments := 1
	if len(frame) > plan.MaxPayloadBytes {
		totalFragments = (len(frame) + plan.MaxPayloadBytes - 1) / plan.MaxPayloadBytes
	}
	if totalFragments > maxFragments {
		return nil, startIndex, fmt.Errorf("payload requires more than %d DNS fragments", maxFragments)
	}

	out := make([][]byte, 0, totalFragments)
	for fragment := 0; fragment < totalFragments; fragment++ {
		start := fragment * plan.MaxPayloadBytes
		end := start + plan.MaxPayloadBytes
		if end > len(frame) {
			end = len(frame)
		}
		raw, err := buildUplinkFragment(clientID, uint32(offset), uint8(fragment), uint8(totalFragments), frame[start:end])
		if err != nil {
			return nil, startIndex, fmt.Errorf("payload requires more than %d DNS fragments", maxFragments)
		}
		encoded := base36x.EncodeLowerBase36Bytes(raw)
		if len(encoded) > plan.MaxEncodedChars {
			return nil, startIndex, fmt.Errorf("encoded fragment exceeds domain capacity")
		}
		labelBytes, err := dnswire.InsertLabels(encoded, maxLabelLen)
		if err != nil {
			return nil, startIndex, err
		}
		qname := make([]byte, 0, len(labelBytes)+len(plan.Encoded))
		qname = append(qname, labelBytes...)
		qname = append(qname, plan.Encoded...)
		out = append(out, qname)
	}
	return out, (startIndex + 1) % len(plans), nil
}

func ParseChunk(labels [][]byte, matcher DomainMatcher, matchedSuffixLen, clientIDLen, offsetWidth int) (Chunk, error) {
	_ = matcher
	_ = offsetWidth
	if matchedSuffixLen <= 0 || matchedSuffixLen > len(labels) {
		return Chunk{}, fmt.Errorf("invalid matched suffix len")
	}
	rawPrefixLen := len(labels) - matchedSuffixLen
	if rawPrefixLen <= 0 {
		return Chunk{}, fmt.Errorf("query has no tunnel labels")
	}

	joinedLen := 0
	for _, label := range labels[:rawPrefixLen] {
		joinedLen += len(label)
	}
	joined := make([]byte, 0, joinedLen)
	for _, label := range labels[:rawPrefixLen] {
		joined = append(joined, label...)
	}

	raw, err := base36x.DecodeLowerBase36(joined)
	if err != nil {
		return Chunk{}, fmt.Errorf("decode base36 fragment: %w", err)
	}
	return parseUplinkFragment(raw, clientIDLen)
}

func calculateMaxEncodedChars(maxQNameLen, domainQnameLen, maxLabelLen int) (int, error) {
	best := 0
	for encodedChars := 1; encodedChars <= maxQNameLen; encodedChars++ {
		labelCount := (encodedChars + maxLabelLen - 1) / maxLabelLen
		qnameLen := encodedChars + labelCount + domainQnameLen
		if qnameLen > maxQNameLen {
			break
		}
		best = encodedChars
	}
	if best == 0 {
		return 0, fmt.Errorf("no encoded chars fit")
	}
	return best, nil
}

func calculateMaxRawBytes(maxEncodedChars int) int {
	best := 0
	for rawBytes := 1; rawBytes <= 65535; rawBytes++ {
		if base36x.EncodedLenLowerBase36(rawBytes) > maxEncodedChars {
			break
		}
		best = rawBytes
	}
	return best
}

func buildUplinkFragment(clientID string, offset uint32, fragmentIndex, fragmentCount uint8, payload []byte) ([]byte, error) {
	if fragmentCount == 0 {
		return nil, fmt.Errorf("fragment count must be non-zero")
	}
	if len(clientID) == 0 || len(clientID) > 255 {
		return nil, fmt.Errorf("client id length must be 1..255")
	}

	raw := make([]byte, 1+len(clientID)+uplinkHeaderLength+len(payload))
	raw[0] = byte(len(clientID))
	copy(raw[1:1+len(clientID)], []byte(clientID))
	offsetPos := 1 + len(clientID)
	binary.BigEndian.PutUint32(raw[offsetPos:offsetPos+4], offset)
	raw[offsetPos+4] = fragmentIndex
	raw[offsetPos+5] = fragmentCount
	copy(raw[offsetPos+uplinkHeaderLength:], payload)
	return raw, nil
}

func parseUplinkFragment(raw []byte, expectedClientIDLen int) (Chunk, error) {
	if len(raw) < 1+uplinkHeaderLength {
		return Chunk{}, fmt.Errorf("uplink fragment too short")
	}
	clientIDLen := int(raw[0])
	if clientIDLen == 0 {
		return Chunk{}, fmt.Errorf("uplink fragment missing client id")
	}
	if expectedClientIDLen > 0 && clientIDLen != expectedClientIDLen {
		return Chunk{}, fmt.Errorf("unexpected client id len %d", clientIDLen)
	}
	if len(raw) < 1+clientIDLen+uplinkHeaderLength {
		return Chunk{}, fmt.Errorf("uplink fragment header truncated")
	}
	clientID := string(raw[1 : 1+clientIDLen])
	offsetPos := 1 + clientIDLen
	offset := binary.BigEndian.Uint32(raw[offsetPos : offsetPos+4])
	fragmentIndex := raw[offsetPos+4]
	fragmentCount := raw[offsetPos+5]
	if fragmentCount == 0 {
		return Chunk{}, fmt.Errorf("fragment count must be non-zero")
	}
	if int(fragmentIndex) >= int(fragmentCount) {
		return Chunk{}, fmt.Errorf("fragment index out of range")
	}
	payload := append([]byte(nil), raw[offsetPos+uplinkHeaderLength:]...)
	return Chunk{
		ClientID:      clientID,
		Offset:        uint64(offset),
		FragmentIndex: int(fragmentIndex),
		Last:          int(fragmentIndex) == int(fragmentCount)-1,
		EncodedData:   payload,
	}, nil
}
