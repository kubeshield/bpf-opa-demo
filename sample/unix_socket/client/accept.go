package main

import (
	"syscall"
)

func main() {
	sockFile := "/tmp/mysockmysock"

	sfd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		panic(err)
	}

	if err := syscall.Connect(sfd, &syscall.SockaddrUnix{
		Name: sockFile,
	}); err != nil {
		panic(err)
	}

	buf := []byte("hello")
	if _, err := syscall.Write(sfd, buf); err != nil {
		panic(err)
	}
}
