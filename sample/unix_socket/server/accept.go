/*
Copyright The Kubeshield Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"
	"syscall"

	"github.com/davecgh/go-spew/spew"
)

func main() {
	sockFile := "/tmp/mysockmysock"
	_ = os.Remove(sockFile)

	sfd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		panic(err)
	}

	if err := syscall.Bind(sfd, &syscall.SockaddrUnix{
		Name: sockFile,
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
