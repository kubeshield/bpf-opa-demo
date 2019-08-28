package main

import (
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/pkg/cpuonline"

	bpf "github.com/iovisor/gobpf/elf"
	"github.com/pkg/errors"
)

func main() {
	cpuRange, err := cpuonline.Get()
	if err != nil {
		panic(err)
	}

	// 0 indexed, so adding 1
	noCPU := int(cpuRange[len(cpuRange)-1]) + 1

	err = load_bpf_file(noCPU, "bpf/probe.o")
	if err != nil {
		panic(err)
	}
}

func load_bpf_file(noCPU int, filepath string) error {
	m := bpf.NewModule(filepath)
	err := m.Load(map[string]bpf.SectionParams{
		"maps/perf_map": bpf.SectionParams{
			MapMaxEntries: noCPU,
		},
		"maps/frame_scratch_map": bpf.SectionParams{
			MapMaxEntries: noCPU,
		},
		"maps/tmp_scratch_map": bpf.SectionParams{
			MapMaxEntries: noCPU,
		},
		"maps/local_state_map": bpf.SectionParams{
			MapMaxEntries: noCPU,
		},
	})
	if err != nil {
		return err
	}

	progMap := m.Map("tail_map")
	if progMap == nil {
		return errors.New("tail map is nil")
	}

	progs := m.RawTracePointPrograms()

	for _, prog := range progs {
		if strings.Contains(prog.Name, "filler/") {
			eventName := prog.Name[len("raw_tracepoint/filler/"):]
			key, found := lookupFillerID(eventName)
			if !found {
				return errors.Errorf("filler id not found for program: %v", prog.Name)
			}

			value := prog.Fd()

			err = m.UpdateElement(progMap, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
			if err != nil {
				return err
			}
		} else {
			err = m.AttachRawTracepoint(prog.Name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
