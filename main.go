package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/iovisor/gobpf/pkg/cpuonline"
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
	logger   = klogr.New()
	selfName string
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

	err = populateSettingsMap(module)
	if err != nil {
		logger.Error(err, "failed to populate settings map")
		panic(err)
	}

	err = populateSyscallTableMap(module)
	if err != nil {
		logger.Error(err, "error populating syscall table map")
		panic(err)
	}

	err = populateFillerTableMap(module)
	if err != nil {
		logger.Error(err, "error populating syscall table map")
		panic(err)
	}

	err = populateEventTableMap(module)
	if err != nil {
		logger.Error(err, "error populating event table map")
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

func populateSettingsMap(m *elf.Module) error {
	log := logger.WithName("[popultae-settings-map]")

	type bpfSettings struct {
		capture_enabled bool
	}

	settingsMap := m.Map("settings_map")
	key := 0
	settings := bpfSettings{}
	err := m.LookupElement(settingsMap, unsafe.Pointer(&key), unsafe.Pointer(&settings))
	if err != nil {
		log.Error(err, "failed to lookup settings map", "key", key, "settings", settings)
		return err
	}

	settings.capture_enabled = true
	err = m.UpdateElement(settingsMap, unsafe.Pointer(&key), unsafe.Pointer(&settings), 0)
	if err != nil {
		log.Error(err, "failed to update settings map", "key", key, "settings", settings)
		return err
	}

	return nil
}

func readFromPerfMap(module *elf.Module) (*elf.PerfMap, error) {
	receiveChan := make(chan []byte)
	lostChan := make(chan uint64)

	perfMap, err := elf.InitPerfMap(module, "perf_map", receiveChan, lostChan)
	if err != nil {
		return nil, err
	}

	evtDataCh := make(chan []byte, 100000)
	go processEventData(evtDataCh)

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

func processEventData(evtDataCh chan []byte) {
	logger := klogr.New().WithName("[parse-event-data]")

	syscallEventCh := make(chan *syscallEvent, 100000)
	for i := 0; i < 10; i++ {
		go queryToOPA(syscallEventCh)
	}

	for {
		data := <-evtDataCh

		out := &perfEventHeader{}
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, out)
		if err != nil {
			logger.V(6).Info("error reading event header data", "error", err)
			continue
		}

		evt := &syscallEvent{}
		evt.perfEventHeader = out
		evt.Params = make(map[string]interface{})

		// continue reading from perf map until we have all the necessary data
		for len(data) < int(out.Len) {
			data = append(data, <-evtDataCh...)
		}

		data = data[binary.Size(out):]
		paramLens := make([]uint16, out.Nparams)

		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, paramLens)
		if err != nil {
			logger.Error(err, "error reading param length data")
			continue
		}

		data = data[binary.Size(paramLens):]

		params := make([][]byte, out.Nparams)

		for i := 0; i < int(out.Nparams); i++ {
			params[i] = make([]byte, paramLens[i])
			params[i] = data[:paramLens[i]]

			switch i {
			case 0:
				evt.Params["fd"] = binary.LittleEndian.Uint64(params[i])
			case 1:
				evt.Params["dirfd"] = binary.LittleEndian.Uint64(params[i])
			case 2:
				// ignore the last byte \u000
				evt.Params["name"] = string(params[i][:len(params[i])-1])
			case 3:
				evt.Params["flags"] = binary.LittleEndian.Uint32(params[i])
			case 4:
				evt.Params["mode"] = binary.LittleEndian.Uint32(params[i])
			case 5:
				evt.Params["dev"] = binary.LittleEndian.Uint32(params[i])
			}
			data = data[paramLens[i]:]
		}
		syscallEventCh <- evt
	}
}
