package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

type execEvent struct {
	Pid       uint64
	TimeStamp uint64
	Command   [32]byte
}

type eventOutput struct {
	Pid       uint64
	TimeStamp uint64
	Command   string
}

const source string = `

struct data_t {
	u32 pid;
	u64 ts;
	char command[32];
};

BPF_PERF_OUTPUT(events);

int probe_execve(struct pt_regs *ctx) {
	struct data_t data = {};

	data.pid = (bpf_get_current_pid_tgid() >> 32);
	data.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.command, sizeof(data.command));

	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
`

func main() {
	module := bpf.NewModule(source, nil)
	kprobe, err := module.LoadKprobe("probe_execve")
	if err != nil {
		log.Fatal(err)
	}

	funcName := bpf.GetSyscallFnName("execve")

	err = module.AttachKprobe(funcName, kprobe, -1)
	if err != nil {
		log.Fatal(err)
	}

	table := bpf.NewTable(module.TableId("events"), module)
	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal)

	go func() {
		for {
			data := <-channel

			var event execEvent
			err = binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
			if err != nil {
				fmt.Println(err)
			}

			out := eventOutput{
				Pid:       event.Pid,
				TimeStamp: event.TimeStamp,
				Command:   C.GoString((*C.char)(unsafe.Pointer(&event.Command))),
			}

			jsonData, err := json.Marshal(out)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(string(jsonData))
		}

	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
