package srv

import (
	"flag"
	"fmt"
	"log"
	"os"

	"zentral.pro/dmtls/pkg/ca"
)

func ServeCmd() {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fsCAPath := fs.String("ca", "dmtls-ca", "CA path")
	fsIP := fs.String("ip", "0.0.0.0", "IP address")
	fsPort := fs.Int("port", 443, "Port number")
	fsRoot := fs.String("root", ".", "Root folder")

	fs.Parse(os.Args[2:])

	ca := ca.LoadCA(*fsCAPath)
	srvName, err := ca.ServerName()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Serve")
	fmt.Printf(" CA: %s\n", *fsCAPath)
	fmt.Printf(" Listen: %s:%d\n", *fsIP, *fsPort)
	fmt.Printf(" Root: %s\n", *fsRoot)

	url := fmt.Sprintf("https://%s", srvName)
	if *fsPort != 443 {
		url = fmt.Sprintf("%s:%d", url, *fsPort)
	}
	fmt.Printf(" URL: %s\n\n", url)

	log.Fatal(startServer(ca, *fsIP, *fsPort, *fsRoot))
}
