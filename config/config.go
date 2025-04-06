package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Client     string
	ListenAddr string
	ChatPort   int
	IDPath     string
	Entrypoint string
}

const (
	ClientCLI     = "cli"
	ClientBrowser = "browser"
)

func New() Config {
	conf := Config{
		Client:   ClientCLI,
		ChatPort: 7000,
		IDPath:   "",
	}

	client := os.Getenv("M2Y_CLIENT")
	if client != "" {
		conf.Client = client
	}

	listenAddr := os.Getenv("M2Y_LISTEN_ADDRESS")
	if listenAddr != "" {
		conf.ListenAddr = listenAddr
	}

	chatPortVal := os.Getenv("M2Y_CHAT_PORT")
	if chatPortVal != "" {
		chatPort, err := strconv.Atoi(chatPortVal)
		if err != nil {
			panic(fmt.Errorf("error parse M2Y_CHAT_PORT environment: %v", err))
		}
		conf.ChatPort = chatPort
	}

	idPath := os.Getenv("M2Y_ID_PATH")
	if idPath != "" {
		conf.IDPath = idPath
	}

	entrypoint := os.Getenv("M2Y_ENTRYPOINT")
	if entrypoint != "" {
		conf.Entrypoint = entrypoint
	}

	return conf
}
