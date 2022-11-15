package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/inconshreveable/muxado"
	"golang.org/x/net/proxy"
)

//lint:file-ignore ST1006 there is nothing wrong with 'this'

type Ngrok struct {
	sess muxado.Session
}

func ngrokNew(proxy_url string) (Ngrok, error) {
	this := Ngrok{}

	dialer, err := proxy.SOCKS5("tcp", proxy_url, nil, proxy.Direct)
	if err != nil {
		return this, fmt.Errorf("couldn't create socks proxy dialer: %v", err)
	}

	raw_conn, err := dialer.Dial("tcp", "tunnel.ngrok.com:443")
	if err != nil {
		return this, fmt.Errorf("couldn't connect to server: %v", err)
	}

	conn := tls.Client(raw_conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	sess := muxado.Client(conn, &muxado.Config{})
	this.sess = sess

	return this, nil
}

func (this *Ngrok) authenticate(token string) error {
	conn, err := this.sess.Open()
	if err != nil {
		return fmt.Errorf("couldn't open auth session: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte{0, 0, 0, 0})
	conn.Write([]byte(`{"Version":["2"],"ClientId":"","Extra":{"OS":"windows","Arch":"amd64","Authtoken":"` +
		token + `","Version":"3.1.0","Hostname":"tunnel.ngrok.com","UserAgent":"ngrok/3.1.0","Metadata":"","Cookie":"","HeartbeatInterval":10000000000,"HeartbeatTolerance":15000000000,"Fingerprint":null,"UpdateUnsupportedError":"","StopUnsupportedError":"","RestartUnsupportedError":"the ngrok agent does not support remote restarting on Windows","ProxyType":"none","MutualTLS":false,"ServiceRun":false,"ConfigVersion":"2","CustomInterface":false}}`))

	bytes, _, err := bufio.NewReaderSize(conn, 1024).ReadLine()
	if err != nil {
		return fmt.Errorf("couldn't get auth response: %v", err)
	}

	type AuthResponse struct {
		Version string
		Error   string
	}
	res := AuthResponse{}
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		return fmt.Errorf("couldn't decode auth response: %v", err)
	}
	if res.Version != "2" {
		return fmt.Errorf("client version is 2, server reported version %s", res.Version)
	}
	if res.Error != "" {
		return fmt.Errorf("server returned error when authenticating: %s", res.Error)
	}

	return nil
}

func (this *Ngrok) bind(port int) (string, error) {
	conn, err := this.sess.Open()
	if err != nil {
		return "", fmt.Errorf("couldn't open bind session: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte{0, 0, 0, 1})
	conn.Write([]byte(`{"Id":"","Proto":"tcp","ForwardsTo":"localhost:` + strconv.Itoa(port) + `","Opts":{"Addr":"","ProxyProto":0,"IPRestriction":null,"ProtoMiddleware":false,"MiddlewareBytes":null},"Extra":{"Token":"","IPPolicyRef":"","Metadata":""}}`))

	bytes, _, err := bufio.NewReaderSize(conn, 1024).ReadLine()
	if err != nil {
		return "", fmt.Errorf("couldn't read bind response: %v", err)
	}

	type BindResponse struct {
		URL   string
		Error string
	}
	res := BindResponse{}
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		return "", fmt.Errorf("couldn't parse bind response: %v", err)
	}
	if res.Error != "" {
		return "", fmt.Errorf("server returned error when binding: %s", res.Error)
	}

	return res.URL, nil
}

func readInfo(sock net.Conn) (string, error) {
	len_bytes := make([]byte, 8)
	_, err := io.ReadFull(sock, len_bytes)
	if err != nil {
		return "", fmt.Errorf("could not read info length: %v", err)
	}

	len_int := int(len_bytes[1])<<8 | int(len_bytes[0])
	bytes := make([]byte, len_int)
	_, err = io.ReadFull(sock, bytes)
	if err != nil {
		return "", fmt.Errorf("could not read info: %v", err)
	}

	type InfoResponse struct {
		ClientAddr string
	}
	info := InfoResponse{}
	err = json.Unmarshal(bytes, &info)
	if err != nil {
		return "", fmt.Errorf("could not parse info: %v", err)
	}

	addr := info.ClientAddr
	if len(addr) < 1 {
		return "", fmt.Errorf("info not valid (info is %s)", info)
	}
	addr = strings.Trim(addr, "[]")
	addr_split := strings.Split(addr, ":")
	if len(addr_split) != 2 {
		return "", fmt.Errorf("could not parse addr: %s", addr)
	}

	host := addr_split[0]
	port, err := strconv.Atoi(addr_split[1])
	if err != nil {
		return "", fmt.Errorf("could not parse port: %s", addr_split[1])
	}

	return host + ":" + strconv.Itoa(port), nil
}

func (this *Ngrok) accept() (net.Conn, string, error) {
	conn, err := this.sess.Accept()
	if err != nil {
		return nil, "", fmt.Errorf("can't accept from session: %v", err)
	}

	kind := make([]byte, 4)
	_, err = io.ReadFull(conn, kind)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("can't read socket kind information from server: %v", err)
	}

	is_heartbeat := true
	for i := range kind {
		if kind[i] != 0xff {
			is_heartbeat = false
			break
		}
	}

	if is_heartbeat {
		go func() {
			io.Copy(conn, conn)
			conn.Close()
		}()
		return this.accept()
	}

	addr, err := readInfo(conn)
	if err != nil {
		return nil, "", err
	}

	return conn, addr, nil
}
