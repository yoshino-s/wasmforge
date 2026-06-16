package runtime

import (
	"net"
)

// NetworkPolicy defines allowed/denied network targets.
type NetworkPolicy struct {
	AllowRules []NetworkRule
	DenyRules  []NetworkRule
}

// NetworkRule is a CIDR-based network access rule.
type NetworkRule struct {
	Network *net.IPNet
}

// ParseNetworkPolicy parses a policy string like "allow:10.0.0.0/8,deny:*".
func ParseNetworkPolicy(policy string) (*NetworkPolicy, error) {
	// For now, return nil (allow all).
	// Full implementation can be added when security controls are needed.
	if policy == "" {
		return nil, nil
	}
	return &NetworkPolicy{}, nil
}
