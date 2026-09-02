package inventory

const (
	GeneratedPrefix = "pamlt-va-20260804-"
	GeneratedMarker = "managed-by=pam-loadtest;inventory=virtual-assets-20260804"
	ExtensionPrefix = "pamlt-va-20260804-ext1-"
	ExtensionMarker = "managed-by=pam-loadtest;inventory=virtual-assets-20260804-ext1"
	SSHScalePrefix  = "pamlt-va-20260804-sshscale1-"
	SSHScaleMarker  = "managed-by=pam-loadtest;inventory=virtual-assets-20260804-sshscale1"
)

type Spec struct {
	Prefix    string         `json:"prefix"`
	Marker    string         `json:"marker"`
	Nodes     []NodeSpec     `json:"nodes"`
	Protocols []ProtocolSpec `json:"protocols"`
}

type NodeSpec struct {
	Backend string `json:"backend"`
	CIDR    string `json:"cidr"`
	Code    string `json:"code"`
}

type ProtocolSpec struct {
	Name     string         `json:"name"`
	Protocol string         `json:"protocol"`
	DBType   string         `json:"dbType,omitempty"`
	Port     int            `json:"port"`
	PerNode  int            `json:"perNode,omitempty"`
	ByNode   map[string]int `json:"byNode,omitempty"`
}

func (p ProtocolSpec) count(code string) int {
	if p.ByNode != nil {
		return p.ByNode[code]
	}
	return p.PerNode
}

type Asset struct {
	Name          string `json:"name"`
	Marker        string `json:"marker"`
	Backend       string `json:"backend"`
	CIDR          string `json:"cidr"`
	IP            string `json:"ip"`
	Protocol      string `json:"protocol"`
	DBType        string `json:"dbType,omitempty"`
	Port          int    `json:"port"`
	NodeIndex     int    `json:"nodeIndex"`
	ProtocolIndex int    `json:"protocolIndex"`
	GlobalIndex   int    `json:"globalIndex"`
}

func DefaultSpec() Spec {
	return Spec{
		Prefix: GeneratedPrefix,
		Marker: GeneratedMarker,
		Nodes: []NodeSpec{
			{Backend: "10.19.88.145", CIDR: "10.200.0.0/23", Code: "n145"},
			{Backend: "10.19.88.146", CIDR: "10.200.2.0/23", Code: "n146"},
			{Backend: "10.19.88.147", CIDR: "10.200.4.0/23", Code: "n147"},
			{Backend: "10.19.88.149", CIDR: "10.200.6.0/23", Code: "n149"},
		},
		Protocols: []ProtocolSpec{
			{Name: "ssh", Protocol: "ssh", Port: 22, PerNode: 250},
			{Name: "rdp", Protocol: "rdp", Port: 3389, PerNode: 100},
			{Name: "vnc", Protocol: "vnc", Port: 5901, PerNode: 50},
			{Name: "web", Protocol: "web", Port: 8080, PerNode: 50},
			{Name: "mysql", Protocol: "database", DBType: "mysql", Port: 3306, PerNode: 50},
		},
	}
}

func ExtensionSpec() Spec {
	return Spec{
		Prefix: ExtensionPrefix,
		Marker: ExtensionMarker,
		Nodes: []NodeSpec{
			{Backend: "10.19.88.145", CIDR: "10.200.8.0/26", Code: "n145"},
			{Backend: "10.19.88.146", CIDR: "10.200.8.64/26", Code: "n146"},
			{Backend: "10.19.88.147", CIDR: "10.200.8.128/26", Code: "n147"},
			{Backend: "10.19.88.149", CIDR: "10.200.8.192/26", Code: "n149"},
		},
		Protocols: []ProtocolSpec{
			{Name: "rdp", Protocol: "rdp", Port: 3389, PerNode: 25},
			{Name: "web", Protocol: "web", Port: 8080, ByNode: map[string]int{"n145": 13, "n146": 13, "n147": 12, "n149": 12}},
		},
	}
}

func SSHScaleSpec() Spec {
	return Spec{
		Prefix: SSHScalePrefix,
		Marker: SSHScaleMarker,
		Nodes: []NodeSpec{
			{Backend: "10.19.88.145", CIDR: "10.201.0.0/23", Code: "n145"},
			{Backend: "10.19.88.146", CIDR: "10.201.2.0/23", Code: "n146"},
			{Backend: "10.19.88.147", CIDR: "10.201.4.0/23", Code: "n147"},
			{Backend: "10.19.88.149", CIDR: "10.201.6.0/23", Code: "n149"},
		},
		Protocols: []ProtocolSpec{{Name: "ssh", Protocol: "ssh", Port: 22, PerNode: 500}},
	}
}
