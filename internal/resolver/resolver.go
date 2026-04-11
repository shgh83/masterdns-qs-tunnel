package resolver

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	defaultPort      = 53
	maxExpandedHosts = 65536
)

type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

func (e Endpoint) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(e.IP, e.Port)
}

func (e Endpoint) String() string {
	return e.AddrPort().String()
}

type Pool struct {
	endpoints []Endpoint
	next      atomic.Uint64
}

func NewPool(endpoints []Endpoint) (*Pool, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("resolver pool is empty")
	}
	return &Pool{endpoints: endpoints}, nil
}

func (p *Pool) NextN(n int) []Endpoint {
	if n <= 0 {
		n = 1
	}
	out := make([]Endpoint, 0, n)
	start := p.next.Add(uint64(n)) - uint64(n)
	for i := 0; i < n; i++ {
		out = append(out, p.endpoints[int((start+uint64(i))%uint64(len(p.endpoints)))])
	}
	return out
}

func LoadFile(path string) ([]Endpoint, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open resolver file: %w", err)
	}
	defer f.Close()

	lines := make([]string, 0, 32)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan resolver file: %w", err)
	}
	return ParseEntries(lines)
}

func ParseEntries(entries []string) ([]Endpoint, error) {
	out := make([]Endpoint, 0, len(entries))
	seen := map[string]struct{}{}
	for _, raw := range entries {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		target, port, err := parseEntry(line)
		if err != nil {
			return nil, err
		}
		if !target.isPrefix {
			addEndpoint(&out, seen, Endpoint{IP: target.addr, Port: port})
			continue
		}
		count, ok := usableHostCount(target.prefix)
		if !ok || count > maxExpandedHosts {
			return nil, fmt.Errorf("resolver prefix %s expands beyond safe limit", target.prefix)
		}
		first, last := hostRange(target.prefix)
		for addr := first; ; addr = addr.Next() {
			addEndpoint(&out, seen, Endpoint{IP: addr, Port: port})
			if addr == last {
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid resolvers found")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP == out[j].IP {
			return out[i].Port < out[j].Port
		}
		return out[i].IP.Less(out[j].IP)
	})
	return out, nil
}

func addEndpoint(out *[]Endpoint, seen map[string]struct{}, endpoint Endpoint) {
	key := endpoint.String()
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, endpoint)
}

type target struct {
	addr     netip.Addr
	prefix   netip.Prefix
	isPrefix bool
}

func parseEntry(line string) (target, uint16, error) {
	if t, err := parseBareTarget(line); err == nil {
		return t, defaultPort, nil
	}
	host, portPart, err := splitHostPort(line)
	if err != nil {
		return target{}, 0, err
	}
	portValue, err := strconv.Atoi(portPart)
	if err != nil || portValue < 1 || portValue > 65535 {
		return target{}, 0, fmt.Errorf("resolver port %q out of range", portPart)
	}
	t, err := parseBareTarget(host)
	if err != nil {
		return target{}, 0, err
	}
	return t, uint16(portValue), nil
}

func parseBareTarget(value string) (target, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return target{}, fmt.Errorf("invalid resolver prefix %q", value)
		}
		return target{prefix: prefix.Masked(), isPrefix: true}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return target{}, fmt.Errorf("invalid resolver ip %q", value)
	}
	return target{addr: addr.Unmap()}, nil
}

func splitHostPort(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end == -1 {
			return "", "", fmt.Errorf("invalid bracketed address %q", value)
		}
		host := strings.TrimSpace(value[1:end])
		remainder := strings.TrimSpace(value[end+1:])
		if !strings.HasPrefix(remainder, ":") {
			return "", "", fmt.Errorf("missing port in %q", value)
		}
		port := strings.TrimSpace(remainder[1:])
		if host == "" || port == "" {
			return "", "", fmt.Errorf("invalid resolver %q", value)
		}
		return host, port, nil
	}

	lastColon := strings.LastIndexByte(value, ':')
	if lastColon <= 0 || lastColon == len(value)-1 {
		return "", "", fmt.Errorf("invalid resolver %q", value)
	}
	host := strings.TrimSpace(value[:lastColon])
	port := strings.TrimSpace(value[lastColon+1:])
	if host == "" || port == "" {
		return "", "", fmt.Errorf("invalid resolver %q", value)
	}
	return host, port, nil
}

func usableHostCount(prefix netip.Prefix) (int, bool) {
	prefix = prefix.Masked()
	addr := prefix.Addr()

	if addr.Is4() {
		hostBits := 32 - prefix.Bits()
		if hostBits > 31 {
			return 0, false
		}
		if hostBits == 31 {
			return 2, true
		}
		total := 1 << hostBits
		if hostBits == 0 {
			return 1, true
		}
		return total - 2, true
	}

	hostBits := 128 - prefix.Bits()
	if hostBits > 16 {
		return 0, false
	}
	total := 1 << hostBits
	if prefix.Bits() < 127 {
		return total - 1, true
	}
	return total, true
}

func hostRange(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	first := prefix.Addr().Unmap()
	last := prefixLastAddr(prefix)
	if first.Is4() && prefix.Bits() < 31 {
		return first.Next(), prevAddr(last)
	}
	if first.Is6() && prefix.Bits() < 127 {
		return first.Next(), last
	}
	return first, last
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		raw := addr.As4()
		value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		hostBits := 32 - prefix.Bits()
		if hostBits > 0 {
			value |= (uint32(1) << hostBits) - 1
		}
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	raw := addr.As16()
	hostBits := 128 - prefix.Bits()
	for i := 15; i >= 0 && hostBits > 0; i-- {
		if hostBits >= 8 {
			raw[i] = 0xff
			hostBits -= 8
			continue
		}
		raw[i] |= byte((1 << hostBits) - 1)
		hostBits = 0
	}
	return netip.AddrFrom16(raw)
}

func prevAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is4() {
		raw := addr.As4()
		value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		value--
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	raw := addr.As16()
	for i := 15; i >= 0; i-- {
		if raw[i] > 0 {
			raw[i]--
			break
		}
		raw[i] = 0xff
	}
	return netip.AddrFrom16(raw)
}
