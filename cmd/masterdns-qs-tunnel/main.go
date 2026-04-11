package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/blackestwhite/masterdns-qs-tunnel/internal/client"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/config"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/server"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "client":
		runClient(os.Args[2:])
	case "server":
		runServer(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configPath := fs.String("config", "configs/client.example.json", "path to client config")
	_ = fs.Parse(args)

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load client config: %v\n", err)
		os.Exit(1)
	}

	service, err := client.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("masterdns-qs-tunnel client started with client_id=%s\n", service.ClientID())
	if err := service.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "client stopped with error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "configs/server.example.json", "path to server config")
	_ = fs.Parse(args)

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load server config: %v\n", err)
		os.Exit(1)
	}

	service, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create server: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("masterdns-qs-tunnel server listening on %s\n", cfg.Listen)
	if err := service.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server stopped with error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <client|server|version> [flags]\n", os.Args[0])
}
