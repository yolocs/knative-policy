package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
)

type config struct {
	ProxyInboundPort  int `split_words:"true" required:"true"`
	ProxyOutboundPort int `split_words:"true" required:"true"`
	ServicePort       int `split_words:"true" required:"true"`
}

var logger *zap.SugaredLogger

const (
	TableNAT = "nat"

	ChainOutput     = "OUTPUT"
	ChainPrerouting = "PREROUTING"
)

func main() {
	// Parse the environment.
	var env config
	if err := envconfig.Process("", &env); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := configInbound(env, ipt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func configInbound(env config, ipt *iptables.IPTables) error {
	rule := []string{"-p", "tcp", "-i", "eth0", "--dport", strconv.Itoa(env.ServicePort), "-j", "REDIRECT", "--to-port", strconv.Itoa(env.ProxyInboundPort)}
	return ipt.Append(TableNAT, ChainPrerouting, rule...)
}
