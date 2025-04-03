package main

import (
	"flag"
	"fmt"
	"m2y/config"
	"m2y/internal/node"
	"net"
)

var (
	clientFlag     = flag.String("client", "", "cli or browser")
	listenAddrFlag = flag.String("addr", "", "if you have public IP to be as an entrypoint to the network")
	chatPortFlag   = flag.Int("port", 0, "if you choose browser as a client")
	idPathFlag     = flag.String("id_path", "", "path to your identifier key pair")
	entrypointFlag = flag.String("entrypoint", "", "Entrypoint to the network")
)

func main() {
	flag.Parse()

	opts := []config.ConfOpt{}
	if *clientFlag != "" {
		opts = append(opts, config.WithClient(*clientFlag))
	}
	if *listenAddrFlag != "" {
		opts = append(opts, config.WithListenAddr(*listenAddrFlag))
	}
	if *chatPortFlag != 0 {
		opts = append(opts, config.WithChatPort(*chatPortFlag))
	}
	if *idPathFlag != "" {
		opts = append(opts, config.WithIDPath(*idPathFlag))
	}

	conf := config.New(opts...)
	entrypoint, err := net.ResolveTCPAddr("tcp", conf.Entrypoint)
	if err != nil {
		panic(fmt.Errorf("error parse entrypoint address: %v", err))
	}

	n := node.New(conf)

	n.Run(entrypoint)
}
