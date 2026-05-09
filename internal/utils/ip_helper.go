package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/LanodonF/coordinate-foister/internal/logger"
	"inet.af/netaddr"
)

var lookupIP = net.LookupIP

func addTargetToSet(token string, builder *netaddr.IPSetBuilder) error {
	logger.Debug("addTargetToSet called with token:", token)

	ip, ipErr := netaddr.ParseIP(token)
	if ipErr == nil {
		logger.Debug("Token identified as single IP")
		addIPToBuilder(ip, builder)
		return nil
	}

	if isIPRangeToken(token) {
		logger.Debug("Token identified as IP range")
		return addIPRange(token, builder)
	} else if strings.Contains(token, "/") {
		logger.Debug("Token identified as CIDR")
		return addCIDR(token, builder)
	}

	if looksLikeIPLiteral(token) {
		logger.Debug("Token identified as invalid IP literal")
		logger.Err("Error parsing IP:", ipErr)
		return fmt.Errorf("invalid IP '%s': %w", token, ipErr)
	}

	logger.Debug("Token identified as DNS name")
	return addDNSTarget(token, builder)
}

func isIPRangeToken(token string) bool {
	octets := strings.Split(token, ".")
	if len(octets) != 4 {
		return false
	}

	hasRange := false
	for _, octet := range octets {
		if octet == "" {
			return false
		}
		if strings.Contains(octet, "-") {
			parts := strings.Split(octet, "-")
			if len(parts) != 2 || !isDigits(parts[0]) || !isDigits(parts[1]) {
				return false
			}
			hasRange = true
			continue
		}
		if !isDigits(octet) {
			return false
		}
	}

	return hasRange
}

func looksLikeIPLiteral(token string) bool {
	if strings.Contains(token, ":") {
		return true
	}

	octets := strings.Split(token, ".")
	if len(octets) != 4 {
		return false
	}

	for _, octet := range octets {
		if !isDigits(octet) {
			return false
		}
	}
	return true
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func addIPRange(token string, builder *netaddr.IPSetBuilder) error {
	logger.Debug("addIPRange called with token:", token)

	octets := strings.Split(token, ".")
	if len(octets) != 4 {
		logger.Err("Invalid IP range format:", token)
		return fmt.Errorf("invalid IP range format '%s'", token)
	}

	octetRanges := make([][]int, 4)
	for i, octet := range octets {
		var err error
		octetRanges[i], err = parseOctetRange(octet)
		if err != nil {
			logger.Err("Error parsing octet range:", err)
			return fmt.Errorf("invalid octet range '%s': %w", octet, err)
		}
		logger.Debug(fmt.Sprintf("Octet %d expanded to: %v", i, octetRanges[i]))
	}

	expandedCount := 0
	for _, o1 := range octetRanges[0] {
		for _, o2 := range octetRanges[1] {
			for _, o3 := range octetRanges[2] {
				for _, o4 := range octetRanges[3] {
					builder.Add(netaddr.IPv4(uint8(o1), uint8(o2), uint8(o3), uint8(o4)))
					expandedCount++
				}
			}
		}
	}
	logger.Debug(fmt.Sprintf("Added %d expanded IPs from range.", expandedCount))
	return nil
}

func parseOctetRange(octet string) ([]int, error) {
	logger.Debug("parseOctetRange called with octet:", octet)

	if strings.Contains(octet, "-") {
		parts := strings.Split(octet, "-")
		if len(parts) != 2 {
			logger.Err("Invalid range format:", octet)
			return nil, fmt.Errorf("invalid range '%s'", octet)
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start > end || start < 0 || end > 255 {
			logger.Err("Invalid range values:", octet)
			return nil, fmt.Errorf("invalid range '%s'", octet)
		}

		result := make([]int, 0, end-start+1)
		for i := start; i <= end; i++ {
			result = append(result, i)
		}
		logger.Debug(fmt.Sprintf("Range '%s' expanded to: %v", octet, result))
		return result, nil
	}

	value, err := strconv.Atoi(octet)
	if err != nil || value < 0 || value > 255 {
		logger.Err("Invalid single octet value:", octet)
		return nil, fmt.Errorf("invalid octet '%s'", octet)
	}
	logger.Debug(fmt.Sprintf("Single octet '%s' parsed as: %d", octet, value))
	return []int{value}, nil
}

func addCIDR(token string, builder *netaddr.IPSetBuilder) error {
	logger.Debug("addCIDR called with token:", token)

	ips, err := netaddr.ParseIPPrefix(token)
	if err != nil {
		logger.Err("Error parsing CIDR:", err)
		return fmt.Errorf("invalid CIDR '%s': %w", token, err)
	}
	builder.AddRange(ips.Range())
	logger.Debug(fmt.Sprintf("Added CIDR '%s' as range: %s", token, ips.Range()))
	return nil
}

func addIPToBuilder(ip netaddr.IP, builder *netaddr.IPSetBuilder) {
	builder.Add(ip)
	logger.Debug(fmt.Sprintf("Added single IP '%s' to builder.", ip))
}

func addDNSTarget(token string, builder *netaddr.IPSetBuilder) error {
	logger.Debug("addDNSTarget called with token:", token)

	resolvedIPs, err := lookupIP(token)
	if err != nil {
		logger.Err("Error resolving DNS target:", err)
		return fmt.Errorf("failed to resolve DNS target '%s': %w", token, err)
	}

	added := false
	for _, resolvedIP := range resolvedIPs {
		if resolvedIP == nil {
			continue
		}

		ip, ok := netaddr.FromStdIP(resolvedIP)
		if !ok {
			logger.Warning(fmt.Sprintf("Skipping unusable DNS result '%s' for target '%s'", resolvedIP, token))
			continue
		}

		builder.Add(ip)
		added = true
		logger.Debug(fmt.Sprintf("Added DNS target '%s' result '%s' to builder.", token, ip))
	}

	if !added {
		return fmt.Errorf("DNS target '%s' resolved to no usable IP addresses", token)
	}

	return nil
}

func extractIPsAndRanges(ipSet *netaddr.IPSet) ([]netaddr.IP, []string) {
	logger.Debug("extractIPsAndRanges called.")

	var individualIPs []netaddr.IP
	var stringAddresses []string

	for _, r := range ipSet.Ranges() {
		logger.Debug(fmt.Sprintf("Processing IP range: %s", r))

		if r.From().Compare(r.To()) != 0 {
			stringAddresses = append(stringAddresses, r.String())
		} else {
			stringAddresses = append(stringAddresses, r.From().String())
		}

		for ip := r.From(); ip.Compare(r.To().Next()) != 0; ip = ip.Next() {
			individualIPs = append(individualIPs, ip)
		}
	}

	logger.Debug(fmt.Sprintf("Extracted %d individual IPs and %d string ranges.", len(individualIPs), len(stringAddresses)))
	return individualIPs, stringAddresses
}
