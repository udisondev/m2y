package main

import (
	"flag"
	"m2y/config"
	"m2y/internal/node"
	"sync"
	"time"
)

var (
	clientFlag     = flag.String("client", "", "cli or browser")
	listenAddrFlag = flag.String("addr", "", "if you have public IP to be as an entrypoint to the network")
	chatPortFlag   = flag.Int("port", 0, "if you choose browser as a client")
	idPathFlag     = flag.String("id_path", "", "path to your identifier key pair")
	entrypointFlag = flag.String("entrypoint", "", "Entrypoint to the network")
)

func main() {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runInstance(config.Config{
			Client:     config.ClientCLI,
			ListenAddr: "localhost:8000",
			ChatPort:   0,
		})
	}()

	<-time.After(time.Second * 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		runInstance(config.Config{
			Client:     config.ClientCLI,
			Entrypoint: "localhost:8000",
			ChatPort:   0,
		})
	}()

	wg.Wait()

}

func runInstance(conf config.Config) {
	n := node.New(conf)
	n.Run()
	select {}
}
