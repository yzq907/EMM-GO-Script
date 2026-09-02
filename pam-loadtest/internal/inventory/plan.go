package inventory

import (
	"fmt"
	"net/netip"
)

func Plan(spec Spec) ([]Asset, error) {
	if spec.Prefix == "" || spec.Marker == "" {
		return nil, fmt.Errorf("generated prefix and marker are required")
	}
	for _, protocol := range spec.Protocols {
		if protocol.Name == "" || protocol.Protocol == "" || protocol.Port < 1 || (protocol.PerNode < 1 && len(protocol.ByNode) == 0) {
			return nil, fmt.Errorf("invalid protocol specification")
		}
	}

	assets := make([]Asset, 0)
	globalIndex := 0
	for nodeIndex, node := range spec.Nodes {
		prefix, err := netip.ParsePrefix(node.CIDR)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 CIDR for backend %s", node.Backend)
		}
		perNode := 0
		for _, protocol := range spec.Protocols {
			count := protocol.count(node.Code)
			if count < 0 {
				return nil, fmt.Errorf("invalid protocol count for node %s", node.Code)
			}
			perNode += count
		}
		usable := (1 << (32 - prefix.Bits())) - 2
		if perNode > usable {
			return nil, fmt.Errorf("node %s requires %d addresses but %s has %d usable addresses", node.Backend, perNode, prefix, usable)
		}
		address := prefix.Masked().Addr().Next()
		for _, protocol := range spec.Protocols {
			for protocolIndex := 1; protocolIndex <= protocol.count(node.Code); protocolIndex++ {
				globalIndex++
				assets = append(assets, Asset{
					Name:          fmt.Sprintf("%s%s-%s-%04d", spec.Prefix, protocol.Name, node.Code, protocolIndex),
					Marker:        spec.Marker,
					Backend:       node.Backend,
					CIDR:          prefix.String(),
					IP:            address.String(),
					Protocol:      protocol.Protocol,
					DBType:        protocol.DBType,
					Port:          protocol.Port,
					NodeIndex:     nodeIndex + 1,
					ProtocolIndex: protocolIndex,
					GlobalIndex:   globalIndex,
				})
				address = address.Next()
			}
		}
	}
	return assets, nil
}

func CombinedPlan() ([]Asset, error) {
	base, err := Plan(DefaultSpec())
	if err != nil {
		return nil, err
	}
	extension, err := Plan(ExtensionSpec())
	if err != nil {
		return nil, err
	}
	combined := append(base, extension...)
	names := make(map[string]struct{}, len(combined))
	addresses := make(map[string]struct{}, len(combined))
	for _, asset := range combined {
		if _, exists := names[asset.Name]; exists {
			return nil, fmt.Errorf("combined plan contains duplicate name %s", asset.Name)
		}
		if _, exists := addresses[asset.IP]; exists {
			return nil, fmt.Errorf("combined plan contains duplicate address %s", asset.IP)
		}
		names[asset.Name] = struct{}{}
		addresses[asset.IP] = struct{}{}
	}
	return combined, nil
}

func CapacityPlan() ([]Asset, error) {
	combined, err := CombinedPlan()
	if err != nil {
		return nil, err
	}
	sshScale, err := Plan(SSHScaleSpec())
	if err != nil {
		return nil, err
	}
	capacity := append(combined, sshScale...)
	names := make(map[string]struct{}, len(capacity))
	addresses := make(map[string]struct{}, len(capacity))
	for _, asset := range capacity {
		if _, exists := names[asset.Name]; exists {
			return nil, fmt.Errorf("capacity plan contains duplicate name %s", asset.Name)
		}
		if _, exists := addresses[asset.IP]; exists {
			return nil, fmt.Errorf("capacity plan contains duplicate address %s", asset.IP)
		}
		names[asset.Name] = struct{}{}
		addresses[asset.IP] = struct{}{}
	}
	return capacity, nil
}
