# ngtor
ngtor is an ngrok client that connects to ngrok over TOR, allowing one to host a TCP service anonymously:

1. Download the repository, `go build .`
2. Sign up for ngrok via TOR, get the auth token.
3. Run `./ngtor <auth-token> <local-port>`

ngtor does not utilize the official ngrok client and makes only one connection during its lifetime, a TLS connection to `tunnel.ngrok.com:443` over the TOR builtin socks5 proxy. The hostname is resolved through the proxy.