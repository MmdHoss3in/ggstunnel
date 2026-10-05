package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"ggstunnel/internal/forward"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Forwards      []forward.Rule    `json:"forwards,omitempty"`
	Tuner         TunerConfig       `json:"tuner"`
	Telemetry     TelemetryConfig   `json:"telemetry"`
	Mode          string            `json:"mode"`
	ConfigVersion int               `json:"config_version"`
	Role          string            `json:"role"`
	Profile       string            `json:"profile"`
	PSK           string            `json:"psk"`
	Real          RealConfig        `json:"real"`
	TUN           TUNConfig         `json:"tun"`
	Transport     TransportConfig   `json:"transport"`
	Performance   PerformanceConfig `json:"performance"`
	LogLevel      string            `json:"log_level"`
}

type TunerConfig struct {
	UnlimitedRate bool   `json:"unlimited_rate,omitempty"`
	Mode          string `json:"mode"`
	MinRTOMS      int    `json:"min_rto_ms"`
	MaxRTOMS      int    `json:"max_rto_ms"`
	MaxPPS        int    `json:"max_pps"`
	MaxBurst      int    `json:"max_burst"`
}
type TelemetryConfig struct {
	StatsFile   string `json:"stats_file,omitempty"`
	IntervalSec int    `json:"interval_sec"`
}

type RealConfig struct {
	LocalIP    string `json:"local_ip"`
	PeerIP     string `json:"peer_ip"`
	ListenAddr string `json:"listen_addr"`
	PeerAddr   string `json:"peer_addr"`
	Interface  string `json:"interface"`
}

type TUNConfig struct {
	Name       string   `json:"name"`
	LocalAddr  string   `json:"local_addr"`
	RemoteAddr string   `json:"remote_addr"`
	Prefix     int      `json:"prefix"`
	MTU        int      `json:"mtu"`
	TxQueueLen int      `json:"tx_queue_len"`
	Routes     []string `json:"routes"`
}

type TransportConfig struct {
	L4Port           int `json:"l4_port"`
	HeartbeatSec     int `json:"heartbeat_sec"`
	IdleTimeoutSec   int `json:"idle_timeout_sec"`
	RetryIntervalSec int `json:"retry_interval_sec"`
	DialTimeoutSec   int `json:"dial_timeout_sec"`
	SockBuf          int `json:"sock_buf"`
	BIPProbeMS       int `json:"bip_probe_ms"`   // legacy/compat display value
	BIPRedundancy    int `json:"bip_redundancy"` // legacy; v2 uses BIPMaxRetries
	BIPFastProbeMS   int `json:"bip_fast_probe_ms"`
	BIPFastTTLMS     int `json:"bip_fast_ttl_ms"`
	BIPNeedPullMS    int `json:"bip_need_pull_ms"`
	BIPPullPPS       int `json:"bip_pull_pps"`
	BIPPullBurst     int `json:"bip_pull_burst"`
	BIPPullHoldMS    int `json:"bip_pull_hold_ms"`
	BIPPullTimeoutMS int `json:"bip_pull_timeout_ms"`
	BIPAckMS         int `json:"bip_ack_ms"`
	BIPRTOMS         int `json:"bip_rto_ms"`
	BIPMaxRetries    int `json:"bip_max_retries"`
	ICMPType         int `json:"icmp_type"`
	ICMPCode         int `json:"icmp_code"`

	BIPDeadTimeoutSec int `json:"bip_dead_timeout_sec"`
	BIPHandshakeTimeoutSec int `json:"bip_handshake_timeout_sec"`
}

type PerformanceConfig struct {
	Profile         string `json:"profile"`
	QueueSize       int    `json:"queue_size"`
	MaxFramePayload int    `json:"max_frame_payload"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("config must contain exactly one JSON object")
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) ApplyDefaults() {
	if c.Tuner.Mode == "" {
		c.Tuner.Mode = "manual"
	}
	if c.Tuner.MinRTOMS == 0 {
		c.Tuner.MinRTOMS = 50
	}
	if c.Tuner.MaxRTOMS == 0 {
		c.Tuner.MaxRTOMS = 10000
	}
	if c.Tuner.MaxPPS == 0 {
		c.Tuner.MaxPPS = 10000
	}
	if c.Tuner.MaxBurst == 0 {
		c.Tuner.MaxBurst = 16
	}
	if c.Telemetry.IntervalSec == 0 {
		c.Telemetry.IntervalSec = 5
	}
	if c.Mode == "" {
		c.Mode = "tun"
	}
	if c.ConfigVersion == 0 {
		c.ConfigVersion = 1
	}
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	c.Profile = strings.ToLower(strings.TrimSpace(c.Profile))
	if c.TUN.Name == "" {
		c.TUN.Name = "ggs0"
	}
	if c.TUN.Prefix == 0 {
		c.TUN.Prefix = 30
	}
	mtu, txq, queue, payload := 1280, 256, 8192, 1280
	switch strings.ToLower(c.Performance.Profile) {
	case "gaming", "low_latency":
		mtu, txq, queue, payload = 1240, 256, 1024, 1240
	case "speed":
		mtu, txq, queue, payload = 1348, 256, 8192, 1348
	}
	if c.Profile == "bip" && c.TUN.TxQueueLen == 0 {
		txq = 1024
	}
	if c.TUN.MTU == 0 {
		c.TUN.MTU = mtu
	}
	if c.TUN.TxQueueLen == 0 {
		c.TUN.TxQueueLen = txq
	}
	if c.Performance.QueueSize == 0 {
		c.Performance.QueueSize = queue
	}
	if c.Performance.MaxFramePayload == 0 {
		c.Performance.MaxFramePayload = payload
	}
	if c.Transport.L4Port == 0 {
		c.Transport.L4Port = 443
	}
	if c.Transport.HeartbeatSec == 0 {
		c.Transport.HeartbeatSec = 10
	}
	if c.Transport.IdleTimeoutSec == 0 {
		c.Transport.IdleTimeoutSec = 90
	}
	if c.Transport.RetryIntervalSec == 0 {
		c.Transport.RetryIntervalSec = 2
	}
	if c.Transport.DialTimeoutSec == 0 {
		c.Transport.DialTimeoutSec = 10
	}
	if c.Transport.SockBuf == 0 {
		c.Transport.SockBuf = 4 << 20
	}
	if c.Transport.BIPProbeMS == 0 {
		c.Transport.BIPProbeMS = 700
	}
	if c.Transport.BIPRedundancy == 0 {
		c.Transport.BIPRedundancy = 1
	}
	if c.Transport.BIPFastProbeMS == 0 {
		c.Transport.BIPFastProbeMS = 1000
	}
	if c.Transport.BIPFastTTLMS == 0 {
		c.Transport.BIPFastTTLMS = 3500
	}
	if c.Transport.BIPNeedPullMS == 0 {
		c.Transport.BIPNeedPullMS = 20
	}
	if c.Transport.BIPPullHoldMS == 0 {
		c.Transport.BIPPullHoldMS = 120
	}
	if c.Transport.BIPPullTimeoutMS == 0 {
		c.Transport.BIPPullTimeoutMS = 300
	}
	if c.Transport.BIPAckMS == 0 {
		c.Transport.BIPAckMS = 10
	}
	if c.Transport.BIPRTOMS == 0 {
		c.Transport.BIPRTOMS = 250
	}
	if c.Transport.BIPMaxRetries == 0 {
		c.Transport.BIPMaxRetries = 8
	}
	if c.Transport.BIPDeadTimeoutSec == 0 {
		c.Transport.BIPDeadTimeoutSec = max(90, c.Transport.BIPFastTTLMS/1000+1)
	}
	if c.Transport.BIPHandshakeTimeoutSec == 0 {
		c.Transport.BIPHandshakeTimeoutSec = 90
	}
	if c.Transport.ICMPType == 0 {
		c.Transport.ICMPType = 8
	}
	if c.Performance.Profile == "" {
		c.Performance.Profile = "stable"
	}
	if c.Performance.QueueSize == 0 {
		c.Performance.QueueSize = 4096
	}
	if c.Performance.MaxFramePayload == 0 {
		c.Performance.MaxFramePayload = 1280
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Transport.BIPPullPPS == 0 {
		switch strings.ToLower(c.Performance.Profile) {
		case "gaming", "low_latency":
			c.Transport.BIPPullPPS = 8000
		case "speed":
			c.Transport.BIPPullPPS = 16000
		default:
			c.Transport.BIPPullPPS = 10000
		}
	}
	if c.Transport.BIPPullBurst == 0 {
		switch strings.ToLower(c.Performance.Profile) {
		case "gaming", "low_latency":
			c.Transport.BIPPullBurst = 8
		case "speed":
			c.Transport.BIPPullBurst = 24
		default:
			c.Transport.BIPPullBurst = 16
		}
	}

	if c.Real.ListenAddr == "" && (c.Profile == "tcp" || c.Profile == "udp") {
		c.Real.ListenAddr = fmt.Sprintf("0.0.0.0:%d", c.Transport.L4Port)
	}
	if c.Real.PeerAddr == "" && c.Real.PeerIP != "" && (c.Profile == "tcp" || c.Profile == "udp") {
		c.Real.PeerAddr = net.JoinHostPort(c.Real.PeerIP, fmt.Sprintf("%d", c.Transport.L4Port))
	}
}

func (c *Config) Validate() error {
	if len(c.Forwards) > 128 {
		return errors.New("at most 128 forward rules")
	}
	for _, r := range c.Forwards {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return errors.New("forward protocol must be tcp or udp")
		}
		for _, addr := range []string{r.Listen, r.Target} {
			host, port, err := net.SplitHostPort(addr)
			if err != nil || net.ParseIP(host).To4() == nil {
				return errors.New("forward requires IPv4:port")
			}
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("invalid forward port")
			}
		}
		host, _, _ := net.SplitHostPort(r.Target)
		if host != c.TUN.RemoteAddr {
			return errors.New("forward target must be remote TUN address")
		}
	}

	if c.Tuner.Mode != "manual" && c.Tuner.Mode != "adaptive" {
		return errors.New("tuner.mode must be manual or adaptive")
	}
	if c.Tuner.MinRTOMS < 10 || c.Tuner.MaxRTOMS > 60000 || c.Tuner.MaxRTOMS < c.Tuner.MinRTOMS {
		return errors.New("tuner RTO bounds must be ordered within 10..60000 ms")
	}
	if c.Tuner.MaxPPS < 1 || c.Tuner.MaxPPS > 100000 || c.Tuner.MaxBurst < 1 || c.Tuner.MaxBurst > 128 {
		return errors.New("tuner rate must be 1..100000 pps and burst 1..128")
	}
	if c.Tuner.Mode == "adaptive" && c.Profile != "bip" {
		return errors.New("adaptive tuner currently requires bip")
	}
	if c.Telemetry.IntervalSec < 1 || c.Telemetry.IntervalSec > 60 {
		return errors.New("telemetry.interval_sec must be 1..60")
	}

	if c.Mode != "" && c.Mode != "tun" {
		return errors.New("this release supports only mode=tun")
	}
	if c.ConfigVersion != 0 && c.ConfigVersion != 1 {
		return errors.New("unsupported config_version")
	}
	if c.Role != "server" && c.Role != "client" {
		return errors.New("role must be server or client")
	}
	switch c.Profile {
	case "tcp", "udp", "icmp", "gre", "ipip", "bip":
	default:
		return fmt.Errorf("unsupported profile %q", c.Profile)
	}
	if len(c.TUN.Name) == 0 || len(c.TUN.Name) > 15 || strings.ContainsAny(c.TUN.Name, "/ \t\n\x00") {
		return errors.New("invalid TUN interface name")
	}
	if c.Performance.QueueSize < 1 || c.Performance.QueueSize > 65536 {
		return errors.New("queue_size must be 1..65536")
	}
	if c.TUN.TxQueueLen < 1 || c.TUN.TxQueueLen > 65536 {
		return errors.New("tx_queue_len must be 1..65536")
	}
	for name, v := range map[string]int{"heartbeat_sec": c.Transport.HeartbeatSec, "idle_timeout_sec": c.Transport.IdleTimeoutSec, "retry_interval_sec": c.Transport.RetryIntervalSec, "dial_timeout_sec": c.Transport.DialTimeoutSec} {
		if v < 1 || v > 86400 {
			return fmt.Errorf("%s must be 1..86400", name)
		}
	}
	if c.Transport.SockBuf < 4096 || c.Transport.SockBuf > 64<<20 {
		return errors.New("sock_buf must be 4096..67108864")
	}
	if c.Transport.L4Port < 1 || c.Transport.L4Port > 65535 {
		return errors.New("l4_port must be 1..65535")
	}
	for _, r := range c.TUN.Routes {
		if _, _, err := net.ParseCIDR(r); err != nil {
			return fmt.Errorf("invalid route %q", r)
		}
	}
	local, peer := net.ParseIP(c.TUN.LocalAddr), net.ParseIP(c.TUN.RemoteAddr)
	if local != nil && peer != nil && (local.Equal(peer) || (local.To4() == nil) != (peer.To4() == nil)) {
		return errors.New("TUN peers must be distinct and use the same address family")
	}
	if len(c.PSK) < 12 {
		return errors.New("psk must be at least 12 characters")
	}
	if net.ParseIP(c.TUN.LocalAddr) == nil || net.ParseIP(c.TUN.RemoteAddr) == nil {
		return errors.New("tun.local_addr and tun.remote_addr must be IP addresses")
	}
	maxPrefix := 32
	if local != nil && local.To4() == nil {
		maxPrefix = 128
		if c.TUN.MTU < 1280 {
			return errors.New("IPv6 TUN MTU must be at least 1280")
		}
	}
	if c.TUN.Prefix < 1 || c.TUN.Prefix > maxPrefix {
		return errors.New("tun.prefix must be 1..32")
	}
	if c.TUN.MTU < 576 || c.TUN.MTU > 9000 {
		return errors.New("tun.mtu must be 576..9000")
	}
	if c.Performance.MaxFramePayload < 256 || c.Performance.MaxFramePayload > 60000 {
		return errors.New("performance.max_frame_payload must be 256..60000")
	}
	if c.Profile == "bip" {
		if net.ParseIP(c.Real.LocalIP).To4() == nil || net.ParseIP(c.Real.PeerIP).To4() == nil {
			return errors.New("BIP currently requires IPv4 outer addresses")
		}
		for name, v := range map[string]int{"bip_probe_ms": c.Transport.BIPProbeMS, "bip_fast_probe_ms": c.Transport.BIPFastProbeMS, "bip_fast_ttl_ms": c.Transport.BIPFastTTLMS, "bip_need_pull_ms": c.Transport.BIPNeedPullMS, "bip_pull_hold_ms": c.Transport.BIPPullHoldMS, "bip_pull_timeout_ms": c.Transport.BIPPullTimeoutMS, "bip_ack_ms": c.Transport.BIPAckMS, "bip_rto_ms": c.Transport.BIPRTOMS} {
			if v < 1 || v > 3600000 {
				return fmt.Errorf("%s must be 1..3600000", name)
			}
		}
		if c.Transport.BIPMaxRetries < 0 || c.Transport.BIPMaxRetries > 32 {
			return errors.New("bip_max_retries must be 0..32")
		}
		if c.Transport.BIPDeadTimeoutSec < 1 || c.Transport.BIPDeadTimeoutSec > 86400 ||
			time.Duration(c.Transport.BIPDeadTimeoutSec)*time.Second <= time.Duration(c.Transport.BIPFastTTLMS)*time.Millisecond {
			return errors.New("transport.bip_dead_timeout_sec must be 1..86400 and exceed bip_fast_ttl_ms")
		}
		if c.Transport.BIPHandshakeTimeoutSec < 1 || c.Transport.BIPHandshakeTimeoutSec > 86400 {
			return errors.New("transport.bip_handshake_timeout_sec must be 1..86400")
		}

		if c.Performance.MaxFramePayload > 1348 {
			return errors.New("BIP5 max_frame_payload must be <= 1348 for a 1500-byte outer MTU")
		}
		if c.Transport.BIPPullPPS < 100 || c.Transport.BIPPullPPS > 100000 {
			return errors.New("transport.bip_pull_pps must be 100..100000")
		}
		if c.Transport.BIPPullBurst < 1 || c.Transport.BIPPullBurst > 128 {
			return errors.New("transport.bip_pull_burst must be 1..128")
		}
		if c.Transport.BIPFastTTLMS <= c.Transport.BIPFastProbeMS {
			return errors.New("transport.bip_fast_ttl_ms must be greater than bip_fast_probe_ms")
		}
	}
	if c.Profile == "udp" && (c.Real.ListenAddr == "" || c.Real.PeerAddr == "") {
		return errors.New("UDP requires fixed listen_addr and peer_addr on both sides")
	}
	if c.Profile == "icmp" || c.Profile == "gre" || c.Profile == "ipip" {
		if net.ParseIP(c.Real.LocalIP).To4() == nil || net.ParseIP(c.Real.PeerIP).To4() == nil {
			return errors.New("raw transport requires IPv4 outer addresses")
		}
		if c.Performance.MaxFramePayload > 1348 {
			return errors.New("raw max_frame_payload must be <=1348")
		}
	}
	if c.Profile == "tcp" || c.Profile == "udp" {
		if c.Role == "server" && c.Real.ListenAddr == "" {
			return errors.New("real.listen_addr is required for server tcp/udp")
		}
		if c.Role == "client" && c.Real.PeerAddr == "" {
			return errors.New("real.peer_addr is required for client tcp/udp")
		}
	} else {
		if net.ParseIP(c.Real.LocalIP) == nil || net.ParseIP(c.Real.PeerIP) == nil {
			return fmt.Errorf("real.local_ip and real.peer_ip are required for raw profile %s", c.Profile)
		}
	}
	return nil
}

func (c *Config) Heartbeat() time.Duration {
	return time.Duration(c.Transport.HeartbeatSec) * time.Second
}
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.Transport.IdleTimeoutSec) * time.Second
}
func (c *Config) RetryInterval() time.Duration {
	return time.Duration(c.Transport.RetryIntervalSec) * time.Second
}
func (c *Config) DialTimeout() time.Duration {
	return time.Duration(c.Transport.DialTimeoutSec) * time.Second
}
