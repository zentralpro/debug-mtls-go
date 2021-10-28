package main

import (
	"fmt"
	"os"

	"zentral.pro/dmtls/pkg/ca"
	"zentral.pro/dmtls/pkg/srv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("expected 'serve' or 'setup' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		srv.ServeCmd()
	case "setup":
		ca.SetupCmd()
	default:
		fmt.Println("expected 'serve' or 'setup' subcommands")
		os.Exit(1)
	}
}
