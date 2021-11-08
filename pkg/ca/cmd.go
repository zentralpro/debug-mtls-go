package ca

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func SetupCmd() {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fsECDSA := fs.Bool("ecdsa", false, "Use ECDSA keys")
	fsCAPath := fs.String("ca", "dmtls-ca", "CA path")
	fsSrvName := fs.String("server-name", "dmtls-server", "server name")
	fsCliName := fs.String("client-name", "dmtls-client", "client name")

	fs.Parse(os.Args[2:])

	fmt.Println("Setup CA")
	var keyType string
	if *fsECDSA {
		keyType = "ECDSA"
	} else {
		keyType = "RSA"
	}
	fmt.Printf(" Key type: %s\n", keyType)
	fmt.Printf(" Path: %s\n", *fsCAPath)
	fmt.Printf(" Server name: %s\n", *fsSrvName)
	fmt.Printf(" Client name: %s\n\n", *fsCliName)

	ca := NewCA(*fsCAPath, *fsECDSA)
	if err := ca.Setup(*fsSrvName, *fsCliName); err != nil {
		log.Fatal(err)
	}
	log.Print("Done")
}
