package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/limrun-inc/limguard"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage()
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "run":
		err = limguard.Run(ctx, os.Args[2:], nil)
	case "apply":
		err = limguard.Apply(ctx, os.Args[2:], nil)
	case "version":
		fmt.Println(limguard.Version)
		return 0
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		usage()
		return 1
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Println(`limguard - WireGuard mesh network manager

Commands:
  run        Run the daemon (bootstraps if needed)
  apply      Deploy to nodes via SSH
  version    Print version

Use "limguard <command> --help" for more information about a command.`)
}
