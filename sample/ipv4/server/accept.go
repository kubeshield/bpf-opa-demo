package main

import (
	"syscall"

	"github.com/davecgh/go-spew/spew"
)

func main() {
	sfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		panic(err)
	}

	if err := syscall.Bind(sfd, &syscall.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{},
	}); err != nil {
		panic(err)
	}

	if err := syscall.Listen(sfd, 5); err != nil {
		panic(err)
	}

	for {
		cfd, _, err := syscall.Accept(sfd)
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 10)
		for {
			n, err := syscall.Read(cfd, buf)
			if err != nil {
				panic(err)
			}
			if n <= 0 {
				break
			}
			spew.Dump(buf[:n])
		}

		_ = syscall.Close(cfd)
	}
}
