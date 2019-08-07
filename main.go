package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	bpf "github.com/iovisor/gobpf/elf"
)

type bpf_output struct {
	Command string
}

type ExecveData struct {
	Command [64]byte
}

func main() {
	module := bpf.NewModule("bpf/raw_tracepoint.o")
	err := module.Load(nil)
	if err != nil {
		panic(err)
	}
	err = module.AttachRawTracepoint("raw_tracepoint/sys_enter")
	if err != nil {
		panic(err)
	}

	bpfEvents := make(chan []byte, 64)
	lostBPFEvents := make(chan uint64, 1)
	perfMap, err := bpf.InitPerfMap(module, "my_map", bpfEvents, lostBPFEvents)
	if err != nil {
		panic(err)
	}

	sig := make(chan os.Signal)

	go func() {
		for {
			select {
			case data := <-bpfEvents:
				var execveData ExecveData
				err = binary.Read(bytes.NewReader(data), binary.LittleEndian, &execveData)
				if err != nil {
					log.Println(err)
				}
				out := bpf_output{
					Command: C.GoString((*C.char)(unsafe.Pointer(&execveData.Command))),
				}
				spew.Dump(out)

			case count := <-lostBPFEvents:
				spew.Dump(count)
			}
		}

	}()

	perfMap.PollStart()
	<-sig
	perfMap.PollStop()
}
