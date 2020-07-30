package api

import (
	"fmt"
	"time"
)

// CheckRestart describes if and when a task should be restarted based on
// failing health checks.
type CheckRestart struct {
	Limit          int            `mapstructure:"limit"`
	Grace          *time.Duration `mapstructure:"grace"`
	IgnoreWarnings bool           `mapstructure:"ignore_warnings"`
}

// Canonicalize CheckRestart fields if not nil.
func (c *CheckRestart) Canonicalize() {
	if c == nil {
		return
	}

	if c.Grace == nil {
		c.Grace = timeToPtr(1 * time.Second)
	}
}

// Copy returns a copy of CheckRestart or nil if unset.
func (c *CheckRestart) Copy() *CheckRestart {
	if c == nil {
		return nil
	}

	nc := new(CheckRestart)
	nc.Limit = c.Limit
	if c.Grace != nil {
		g := *c.Grace
		nc.Grace = &g
	}
	nc.IgnoreWarnings = c.IgnoreWarnings
	return nc
}

// Merge values from other CheckRestart over default values on this
// CheckRestart and return merged copy.
func (c *CheckRestart) Merge(o *CheckRestart) *CheckRestart {
	if c == nil {
		// Just return other
		return o
	}

	nc := c.Copy()

	if o == nil {
		// Nothing to merge
		return nc
	}

	if o.Limit > 0 {
		nc.Limit = o.Limit
	}

	if o.Grace != nil {
		nc.Grace = o.Grace
	}

	if o.IgnoreWarnings {
		nc.IgnoreWarnings = o.IgnoreWarnings
	}

	return nc
}

// ServiceCheck represents the consul health check that Nomad registers.
type ServiceCheck struct {
	//FIXME Id is unused. Remove?
	Id            string
	Name          string
	Type          string
	Command       string
	Args          []string
	Path          string
	Protocol      string
	PortLabel     string `mapstructure:"port"`
	Expose        bool
	AddressMode   string `mapstructure:"address_mode"`
	Interval      time.Duration
	Timeout       time.Duration
	InitialStatus string `mapstructure:"initial_status"`
	TLSSkipVerify bool   `mapstructure:"tls_skip_verify"`
	Header        map[string][]string
	Method        string
	CheckRestart  *CheckRestart `mapstructure:"check_restart"`
	GRPCService   string        `mapstructure:"grpc_service"`
	GRPCUseTLS    bool          `mapstructure:"grpc_use_tls"`
	TaskName      string        `mapstructure:"task"`
}

// Service represents a Consul service definition.
type Service struct {
	//FIXME Id is unused. Remove?
	Id                string
	Name              string
	Tags              []string
	CanaryTags        []string `mapstructure:"canary_tags"`
	EnableTagOverride bool     `mapstructure:"enable_tag_override"`
	PortLabel         string   `mapstructure:"port"`
	AddressMode       string   `mapstructure:"address_mode"`
	Checks            []ServiceCheck
	CheckRestart      *CheckRestart `mapstructure:"check_restart"`
	Connect           *ConsulConnect
	Meta              map[string]string
	CanaryMeta        map[string]string
	TaskName          string `mapstructure:"task"`
}

// Canonicalize the Service by ensuring its name and address mode are set. Task
// will be nil for group services.
func (s *Service) Canonicalize(t *Task, tg *TaskGroup, job *Job) {
	if s.Name == "" {
		if t != nil {
			s.Name = fmt.Sprintf("%s-%s-%s", *job.Name, *tg.Name, t.Name)
		} else {
			s.Name = fmt.Sprintf("%s-%s", *job.Name, *tg.Name)
		}
	}

	// Default to AddressModeAuto
	if s.AddressMode == "" {
		s.AddressMode = "auto"
	}

	s.Connect.Canonicalize()

	// Canonicalize CheckRestart on Checks and merge Service.CheckRestart
	// into each check.
	for i, check := range s.Checks {
		s.Checks[i].CheckRestart = s.CheckRestart.Merge(check.CheckRestart)
		s.Checks[i].CheckRestart.Canonicalize()
	}
}

// ConsulConnect represents a Consul Connect jobspec stanza.
type ConsulConnect struct {
	Native         bool
	Gateway        *ConsulGateway
	SidecarService *ConsulSidecarService `mapstructure:"sidecar_service"`
	SidecarTask    *SidecarTask          `mapstructure:"sidecar_task"`
}

func (cc *ConsulConnect) Canonicalize() {
	if cc == nil {
		return
	}

	cc.SidecarService.Canonicalize()
	cc.SidecarTask.Canonicalize()
}

// ConsulSidecarService represents a Consul Connect SidecarService jobspec
// stanza.
type ConsulSidecarService struct {
	Tags  []string
	Port  string
	Proxy *ConsulProxy
}

func (css *ConsulSidecarService) Canonicalize() {
	if css == nil {
		return
	}

	if len(css.Tags) == 0 {
		css.Tags = nil
	}

	css.Proxy.Canonicalize()
}

// SidecarTask represents a subset of Task fields that can be set to override
// the fields of the Task generated for the sidecar
type SidecarTask struct {
	Name          string
	Driver        string
	User          string
	Config        map[string]interface{}
	Env           map[string]string
	Resources     *Resources
	Meta          map[string]string
	KillTimeout   *time.Duration `mapstructure:"kill_timeout"`
	LogConfig     *LogConfig     `mapstructure:"logs"`
	ShutdownDelay *time.Duration `mapstructure:"shutdown_delay"`
	KillSignal    string         `mapstructure:"kill_signal"`
}

func (st *SidecarTask) Canonicalize() {
	if st == nil {
		return
	}

	if len(st.Config) == 0 {
		st.Config = nil
	}

	if len(st.Env) == 0 {
		st.Env = nil
	}

	if st.Resources == nil {
		st.Resources = DefaultResources()
	} else {
		st.Resources.Canonicalize()
	}

	if st.LogConfig == nil {
		st.LogConfig = DefaultLogConfig()
	} else {
		st.LogConfig.Canonicalize()
	}

	if len(st.Meta) == 0 {
		st.Meta = nil
	}

	if st.KillTimeout == nil {
		st.KillTimeout = timeToPtr(5 * time.Second)
	}

	if st.ShutdownDelay == nil {
		st.ShutdownDelay = timeToPtr(0)
	}
}

// ConsulProxy represents a Consul Connect sidecar proxy jobspec stanza.
type ConsulProxy struct {
	LocalServiceAddress string              `mapstructure:"local_service_address"`
	LocalServicePort    int                 `mapstructure:"local_service_port"`
	ExposeConfig        *ConsulExposeConfig `mapstructure:"expose"`
	Upstreams           []*ConsulUpstream
	Config              map[string]interface{}
}

func (cp *ConsulProxy) Canonicalize() {
	if cp == nil {
		return
	}

	cp.ExposeConfig.Canonicalize()

	if len(cp.Upstreams) == 0 {
		cp.Upstreams = nil
	}

	if len(cp.Config) == 0 {
		cp.Config = nil
	}
}

// ConsulUpstream represents a Consul Connect upstream jobspec stanza.
type ConsulUpstream struct {
	DestinationName string `mapstructure:"destination_name"`
	LocalBindPort   int    `mapstructure:"local_bind_port"`
}

type ConsulExposeConfig struct {
	Path []*ConsulExposePath `mapstructure:"path"`
}

func (cec *ConsulExposeConfig) Canonicalize() {
	if cec == nil {
		return
	}

	if len(cec.Path) == 0 {
		cec.Path = nil
	}
}

type ConsulExposePath struct {
	Path          string
	Protocol      string
	LocalPathPort int    `mapstructure:"local_path_port"`
	ListenerPort  string `mapstructure:"listener_port"`
}

// ConsulGateway is used to configure one of the Consul Connect Gateway types.
type ConsulGateway struct {
	// Proxy is used to configure the Envoy instance acting as the gateway.
	Proxy *ConsulGatewayProxy

	// Ingress represents the Consul Configuration Entry for an Ingress Gateway.
	Ingress *ConsulIngressConfigEntry

	// Terminating is not yet supported.
	// Terminating *ConsulTerminatingConfigEntry

	// Mesh is not yet supported.
	// Mesh *ConsulMeshConfigEntry
}

// ConsulGatewayProxy is used to tune parameters of the proxy instance acting as
// one of the forms of Connect gateways that Consul supports.
//
// https://www.consul.io/docs/connect/proxies/envoy#gateway-options
type ConsulGatewayProxy struct {
	ConnectTimeout *time.Duration `mapstructure:"connect_timeout"`

	EnvoyGatewayBindTaggedAddresses bool   `mapstructure:"envoy_gateway_bind_tagged_addresses"`
	EnvoyGatewayBindAddresses       bool   `mapstructure:"envoy_gateway_bind_addresses"`
	EnvoyGatewayNoDefaultBind       bool   `mapstructure:"envoy_gateway_no_default_bind"`
	EnvoyDNSDiscoveryType           string `mapstructure:"envoy_dns_discovery_type"`

	Config map[string]interface{} // escape hatch
}

// ConsulGatewayTLSConfig is used to configure TLS for a gateway.
type ConsulGatewayTLSConfig struct {
	Enabled bool
}

type ConsulIngressService struct {
	// Namespace is not yet supported.
	// Namespace string
	Name string

	Hosts []string
}

// ConsulIngressListener is used to configure a listener on a Consul Ingress
// Gateway.
type ConsulIngressListener struct {
	Port     int
	Protocol string
	Services []*ConsulIngressService
}

// ConsulIngressConfigEntry represents the Consul Configuration Entry type for
// an Ingress Gateway.
//
// https://www.consul.io/docs/agent/config-entries/ingress-gateway#available-fields
type ConsulIngressConfigEntry struct {
	// Namespace is not yet supported.
	// Namespace string

	TLS       *ConsulGatewayTLSConfig
	Listeners []*ConsulIngressListener
}

// ConsulTerminatingConfigEntry is not yet supported.
// type ConsulTerminatingConfigEntry struct {
// }

// ConsulMeshConfigEntry is not yet supported.
// type ConsulMeshConfigEntry struct {
// }
