package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"flag"
	"os"
	"strings"
	"time"
	"unsafe"

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

type rawSyscallData struct {
	perfEventHeader *perfEventHeader
	data            []byte
}

var (
	logger   = klogr.New()
	selfName string
	selfPid  = make(map[int]bool)
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	proc, err := procfs.Self()
	if err != nil {
		panic(err)
	}
	selfName, err = proc.Comm()
	if err != nil {
		panic(err)
	}

	cpuRange, err := cpuonline.Get()
	if err != nil {
		panic(err)
	}

	// 0 indexed, so adding 1
	noCPU := int(cpuRange[len(cpuRange)-1]) + 1

	module, err := load_bpf_file(noCPU, "bpf/probe.o")
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

	perfMap, err := readFromPerfMap(module)
	if err != nil {
		logger.Error(err, "error reading from perf map")
		panic(err)
	}
	defer perfMap.PollStop()

	loadAllProcess()

	sig := make(chan os.Signal)
	<-sig
}

func load_bpf_file(noCPU int, filepath string) (*elf.Module, error) {
	m := elf.NewModule(filepath)
	err := m.Load(map[string]elf.SectionParams{
		"maps/perf_map": elf.SectionParams{
			MapMaxEntries: noCPU,
		},
		"maps/frame_scratch_map": elf.SectionParams{
			MapMaxEntries: noCPU,
		},
		"maps/tmp_scratch_map": elf.SectionParams{
			MapMaxEntries: noCPU,
		},
		"maps/local_state_map": elf.SectionParams{
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

func readFromPerfMap(module *elf.Module) (*elf.PerfMap, error) {
	receiveChan := make(chan []byte)
	lostChan := make(chan uint64)

	perfMap, err := elf.InitPerfMap(module, "perf_map", receiveChan, lostChan)
	if err != nil {
		return nil, err
	}

	evtDataCh := make(chan []byte, 100000)
	go processPerfEventData(evtDataCh)

	go func() {
		for {
			select {
			case data := <-receiveChan:
				evtDataCh <- data

			case data := <-lostChan:
				logger.V(6).Info("lost events", "count", data)
			}
		}
	}()

	perfMap.PollStart()

	return perfMap, nil
}

func processPerfEventData(evtDataCh chan []byte) {
	parseCh := make(chan *rawSyscallData)
	opaQueryCh := make(chan *syscallEvent)
	for i := 0; i < 10; i++ {
		go parseRawSyscallData(parseCh, opaQueryCh)
		go querySyscallEventToOPA(opaQueryCh)
	}

	for {
		data := <-evtDataCh

		out := &perfEventHeader{}
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, out)
		if err != nil {
			logger.V(6).Info("error reading event header data", "error", err)
			continue
		}

		// continue reading from perf map until we have all the necessary data
		for len(data) < int(out.Len) {
			data = append(data, <-evtDataCh...)
		}

		data = data[binary.Size(out):]

		parseCh <- &rawSyscallData{
			perfEventHeader: out,
			data:            data,
		}
	}
}

func loadAllProcess() {
	// wait for all go-routines to start
	time.Sleep(time.Second * 5)

	procs, err := procfs.AllProcs()
	if err != nil {
		logger.Error(err, "failed to read /proc")
	}

	for _, p := range procs {
		name, err := p.Comm()
		if err != nil {
			logger.Error(err, "error reading command name, skipping")
		}
		if name == selfName {
			selfPid[p.PID] = true
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

		process := Process{
			Name:       name,
			Executable: executable,
			Args:       cmdline,
			Cgroup:     []string{containerID},
		}

		processMapLock.Lock()
		processMap[uint64(p.PID)] = process
		processMapLock.Unlock()
	}
}
