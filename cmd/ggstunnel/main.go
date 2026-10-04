package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ggstunnel/internal/config"
	"ggstunnel/internal/engine"
	"ggstunnel/internal/version"
)

var buildVersion = version.Version

func main() {
	cfgPath := flag.String("c", "", "path to JSON config")
	gen := flag.String("gen", "", "print sample config: server|client")
	check := flag.Bool("check", false, "validate config and exit")
	statsFile := flag.String("stats-file", "", "optional private JSON telemetry path")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("ggstunnel", buildVersion)
		return
	}
	if *gen != "" {
		printSample(*gen)
		return
	}
	if *cfgPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	c, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if *statsFile != "" {
		c.Telemetry.StatsFile = *statsFile
	}
	if *check {
		fmt.Printf("OK: role=%s profile=%s tun=%s %s<->%s\n", c.Role, c.Profile, c.TUN.Name, c.TUN.LocalAddr, c.TUN.RemoteAddr)
		return
	}
	e, err := engine.New(c)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := e.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
func printSample(role string) {
	if role != "client" {
		role = "server"
	}
	local, remote := "10.77.1.1", "10.77.1.2"
	realLocal, realPeer := "198.51.100.10", "203.0.113.20"
	if role == "client" {
		local, remote = remote, local
		realLocal, realPeer = realPeer, realLocal
	}
	c := config.Config{Tuner: config.TunerConfig{Mode: "adaptive", MinRTOMS: 50, MaxRTOMS: 10000, MaxPPS: 10000, MaxBurst: 128, UnlimitedRate: true}, Telemetry: config.TelemetryConfig{IntervalSec: 5}, ConfigVersion: 1, Mode: "tun", Role: role, Profile: "bip", PSK: "CHANGE-ME-AT-LEAST-16-CHARS", Real: config.RealConfig{LocalIP: realLocal, PeerIP: realPeer, ListenAddr: "0.0.0.0:443", PeerAddr: realPeer + ":443"}, TUN: config.TUNConfig{Name: "ggs0", LocalAddr: local, RemoteAddr: remote, Prefix: 30, MTU: 1280, TxQueueLen: 1024, Routes: []string{}}, Transport: config.TransportConfig{L4Port: 443, HeartbeatSec: 10, IdleTimeoutSec: 90, RetryIntervalSec: 2, DialTimeoutSec: 10, SockBuf: 4 << 20, BIPProbeMS: 700, BIPRedundancy: 1, BIPFastProbeMS: 1000, BIPFastTTLMS: 3500, BIPNeedPullMS: 20, BIPPullPPS: 10000, BIPPullBurst: 128, BIPPullHoldMS: 120, BIPPullTimeoutMS: 300, BIPAckMS: 10, BIPRTOMS: 250, BIPMaxRetries: 8, ICMPType: 8}, Performance: config.PerformanceConfig{Profile: "stable", QueueSize: 8192, MaxFramePayload: 1280}, LogLevel: "info"}
	b, _ := json.MarshalIndent(c, "", "  ")
	fmt.Println(string(b))
}
