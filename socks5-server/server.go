package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/f0reachARR/go-socks5-server"
)

var addr = flag.String("addr", "127.0.0.1:3000", "Specify address to listen")

func main() {
	flag.Parse()

	listenAddr, err := net.ResolveTCPAddr("tcp", *addr)
	if err != nil {
		log.Fatalln("failed to ResolveTCPAddr", err)
		return
	}

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatalln("failed to ListenTCP", err)
		return
	}

	log.Printf("listen %s", *addr)

	defer listener.Close()
	for {
		conn, err := listener.AcceptTCP()

		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					log.Fatalln("AcceptTCP", err)
					continue
				}
			}
			return
		}

		go handleConnection(conn)
	}
}

func handleConnection(socksConn *net.TCPConn) {
	defer socksConn.Close()

	req := socks5.NewRequest(socksConn)
	if err := req.Negotiate(); err != nil {
		log.Fatalln("failed to Negotiate")
		return
	}

	// To make easier, use Dial
	var target string
	switch req.AddressType {
	case socks5.AddrIPv4:
		target = fmt.Sprintf("%s:%d", req.Address.String(), req.Port)
	case socks5.AddrDns:
		target = fmt.Sprintf("%s:%d", req.Fqdn, req.Port)
	default:
		log.Fatalln("not supported address type")
		return
	}
	clientConn, err := net.Dial("tcp", target)
	if err != nil {
		req.SendResponse(socks5.Response{
			Type:        socks5.ReplyFailed,
			AddressType: socks5.AddrIPv4,
			BindAddress: net.IPv4(127, 0, 0, 1),
			BindPort:    0,
		})
		log.Fatalln("failed to Dial")
		return
	}

	defer clientConn.Close()

	if err := req.SendResponse(socks5.Response{
		Type:        socks5.ReplySuccess,
		AddressType: socks5.AddrIPv4,
		BindAddress: net.IPv4(127, 0, 0, 1),
		BindPort:    req.Port,
	}); err != nil {
		log.Fatalln("failed to SendResponse")
		return
	}

	log.Printf("new conncetion to %s", target)

	done := make(chan struct{})
	go func() {
		io.Copy(clientConn, socksConn)
		clientConn.Close()
		close(done)
	}()
	io.Copy(socksConn, clientConn)
	socksConn.Close()
	<-done

	log.Printf("connection closed")
}
