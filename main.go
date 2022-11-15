package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

const TOR_URL string = "127.0.0.1:9050"
const TOR_BROWSER_URL string = "127.0.0.1:9150"

func main() {
	fmt.Println("welcome to ngtor")

	if len(os.Args) != 3 {
		fmt.Println("usage: ngtor <auth-token> <local-port>")
		os.Exit(1)
	}

	token := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("passed argument for parameter <local-port> is invalid")
		os.Exit(1)
	}

	fmt.Printf("trying TOR on %s...\n", TOR_URL)
	ngrok, err := ngrokNew(TOR_URL)
	if err != nil {
		fmt.Printf("failed: %v\n", err)
		fmt.Printf("trying TOR browser on %s...\n", TOR_BROWSER_URL)
		ngrok, err = ngrokNew(TOR_BROWSER_URL)
		if err != nil {
			fmt.Printf("failed again: %v\n", err)
			fmt.Println("unrecoverable")
			os.Exit(1)
		}
	}

	fmt.Println("note: ngrok uses a self-signed certificate which is not checked by ngtor")
	fmt.Println("      thus traffic may be intercepted and modified at TOR exit node")

	fmt.Println("authenticating with ngrok")
	err = ngrok.authenticate(token)
	if err != nil {
		fmt.Printf("auth failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("binding to port")
	fmt.Println("note: the local port number is forwarded to ngrok servers")
	remote_url, err := ngrok.bind(port)
	if err != nil {
		fmt.Printf("bind failed: %v\n", err)
		os.Exit(1)
	}

	local_url := "127.0.0.1:" + strconv.Itoa(port)
	fmt.Printf("listening on %s --> %s\n", remote_url, local_url)

	for {
		remote, addr, err := ngrok.accept()
		if err != nil {
			fmt.Printf("can't accept connection: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("accepted connection from %s\n", addr)

		go func() {
			local, err := net.Dial("tcp", local_url)
			if err != nil {
				fmt.Printf("could not connect to upstream: %v\n", err)
				return
			}

			go func() {
				io.Copy(local, remote)
				local.Close()
				remote.Close()
			}()

			io.Copy(remote, local)
			local.Close()
			remote.Close()
		}()
	}
}
