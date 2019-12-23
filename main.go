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

import "C"
import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"go.kubeshield.dev/bpf-opa-demo/bpf"

	"github.com/iovisor/gobpf/elf"
	"github.com/iovisor/gobpf/pkg/cpuonline"
	"github.com/pkg/errors"
	"github.com/prometheus/procfs"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
)

type perfEventHeader struct {
	Ts      uint64 `json:"ts"`
	Tid     uint64 `json:"tid"`
	Len     uint32 `json:"len"`
	Type    uint16 `json:"type"`
	Nparams uint32 `json:"nparams"`
}

var (
	logger       = klogr.New()
	selfName     = "bpf-opa-demo"
	selfPidMutex sync.RWMutex
	selfPid      = make(map[int]bool)

	procDir   string
	procDirFS procfs.FS
)

func main() {
	klog.InitFlags(nil)

	flag.StringVar(&procDir, "procdir", "/proc", "")
	flag.Parse()

	logger.Info("starting")

	go func() {
		if err := SetupPodWatcher(); err != nil {
			panic(err)
		}
	}()

	module, err := load_bpf_file()
	if err != nil {
		panic(err)
	}

	procDirFS, err = procfs.NewFS(procDir)
	if err != nil {
		panic(err)
	}

	err = populateMaps(module)
	if err != nil {
		panic(err)
	}

	// load all opa rules
	err = loadRules()
	if err != nil {
		logger.Error(err, "error loading rules to opa api")
		panic(err)
	}

	loadAllProcess()

	ctx, cancelFunc := context.WithCancel(context.Background())

	workerCount := 10
	wg := &sync.WaitGroup{}
	wg.Add(workerCount)

	// start reading from perf map
	go func() {
		if err := readFromPerfMap(ctx, workerCount, wg, module); err != nil {
			logger.Error(err, "error reading from perf map")
			panic(err)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-done

	cancelFunc()

	if err := module.Close(); err != nil {
		logger.Error(err, "failed to close module")
	}
	logger.Info("successfully closed bpf module")

	// wait for all worker goroutines to close
	wg.Wait()
	logger.Info("all worker go-routines successfully exited")

}

func load_bpf_file() (*elf.Module, error) {
	cpuRange, err := cpuonline.Get()
	if err != nil {
		panic(err)
	}

	// 0 indexed, so adding 1
	noCPU := int(cpuRange[len(cpuRange)-1]) + 1

	bpfProgram, err := bpf.Asset("probe.o")
	if err != nil {
		panic(err)
	}

	m := elf.NewModuleFromReader(bytes.NewReader(bpfProgram))
	err = m.Load(map[string]elf.SectionParams{
		"maps/perf_map": {
			MapMaxEntries: noCPU,
		},
		"maps/frame_scratch_map": {
			MapMaxEntries: noCPU,
		},
		"maps/tmp_scratch_map": {
			MapMaxEntries: noCPU,
		},
		"maps/local_state_map": {
			MapMaxEntries: noCPU,
		},
	})
	if err != nil {
		return nil, err
	}

	progMap := m.Map("tail_map")
	if progMap == nil {
		return nil, errors.New("tail map is nil")
	}

	progs := m.RawTracePointPrograms()

	for _, prog := range progs {
		log := logger.WithValues("name", prog.Name, "fd", prog.Fd())

		if strings.Contains(prog.Name, "filler/") {
			eventName := prog.Name[len("raw_tracepoint/filler/"):]
			key, found := lookupFillerID(eventName)
			if !found {
				log.Info("filler id not found")
				return nil, errors.New("filler id not found")
			}

			value := prog.Fd()

			err = m.UpdateElement(progMap, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
			if err != nil {
				log.Error(err, "failed to update prog map", "key", key, "value", value)
				return nil, err
			}

			log.V(6).Info("successfully loaded program to tail_map")

		} else {
			err = m.AttachRawTracepoint(prog.Name)
			if err != nil {
				log.Error(err, "failed to attach program", "progname", prog.Name)
				return nil, err
			}
		}
	}

	return m, nil
}

func readFromPerfMap(ctx context.Context, workerCount int, wg *sync.WaitGroup, module *elf.Module) error {
	receiveChan := make(chan []byte, 100000)
	lostChan := make(chan uint64, 100000)

	perfMap, err := elf.InitPerfMap(module, "perf_map", receiveChan, lostChan)
	if err != nil {
		return err
	}
	perfMap.PollStart()
	defer perfMap.PollStop()

	opaQueryCh := make(chan *syscallEvent, 100000)
	for i := 0; i < workerCount; i++ {
		go querySyscallEventToOPA(wg, opaQueryCh)
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("returning from read from perf map")
			close(opaQueryCh)
			return nil
		case data := <-receiveChan:
			out := &perfEventHeader{}
			err := binary.Read(bytes.NewReader(data), binary.LittleEndian, out)
			if err != nil {
				logger.V(6).Info("error reading event header data", "error", err)
				continue
			}

			// continue reading from perf map until we have all the necessary data
			for len(data) < int(out.Len) {
				data = append(data, <-receiveChan...)
			}

			// ignore this syscall if it is from this program
			selfPidMutex.RLock()
			if selfPid[int(out.Tid)] {
				selfPidMutex.RUnlock()
				continue
			}
			selfPidMutex.RUnlock()

			data = data[binary.Size(out):]
			newdata := make([]byte, len(data))
			copy(newdata, data)

			parseRawSyscallData(out, newdata, opaQueryCh)
		case data := <-lostChan:
			logger.V(6).Info("lost events", "count", data)
		}
	}
}

func loadAllProcess() {
	procs, err := procDirFS.AllProcs()
	if err != nil {
		logger.Error(err, "failed to read /proc")
	}

	for _, p := range procs {
		process := getProcessInfo(p)

		processMapLock.Lock()
		processMap[uint64(p.PID)] = process
		processMapLock.Unlock()
	}
}

func getProcessInfo(p procfs.Proc) Process {
	name, err := p.Comm()
	if err != nil {
		logger.V(6).Info("error reading command name, skipping: ", err.Error())
	}
	if name == selfName {
		selfPidMutex.Lock()
		selfPid[p.PID] = true
		selfPidMutex.Unlock()
	}
	executable, err := p.Executable()
	if err != nil {
		logger.V(6).Info(errors.Wrap(err, "failed to get Process executable").Error())
	}
	cmdline, err := p.CmdLine()
	if err != nil {
		logger.V(6).Info(errors.Wrap(err, "failed to get Process cmdline").Error())
	}
	containerID, err := getContainerIDfromPID(p.PID)
	if err != nil {
		logger.V(6).Info(errors.Wrap(err, "failed to get Process containerid").Error())
	}

	var command string
	var args []string
	if len(cmdline) > 0 {
		command = cmdline[0]
		args = cmdline[1:]
	}

	return Process{
		Name:       name,
		Executable: executable,
		Args:       args,
		Command:    command,
		Cgroup:     []string{containerID},
		Pid:        uint64(p.PID),
	}
}
