package main

import (
	"net"
	"os"
	"syscall"
)

func main() {
	sfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		panic(err)
	}

	// addr := net.IPv4zero.To4()
	// var ipaddr [4]byte
	// for i := 0; i < 4; i++ {
	// 	ipaddr[i] = addr[i]
	// }
	// spew.Dump(ipaddr)

	serverAddress := &syscall.SockaddrInet4{
		Port: 8080,
	}
	copy(serverAddress.Addr[:], net.IPv4zero.To4())

	if err := syscall.Connect(sfd, serverAddress); err != nil {
		panic(err)
	}

	buf := []byte("hello")
	if _, err := syscall.Write(sfd, buf); err != nil {
		panic(err)
	}
	ch := make(chan os.Signal)
	<-ch
}
