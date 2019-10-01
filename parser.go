package main

import (
	"bytes"
	"encoding/binary"

	"github.com/prometheus/procfs"
)

var (
	processMap = map[uint64]Process{}
)

func parseRawSyscallData(parseCh chan *rawSyscallData) {
	for {
		rawSyscallData := <-parseCh
		perfEvtHeader := rawSyscallData.perfEventHeader
		data := rawSyscallData.data

		// oneliners.PrettyJson(perfEvtHeader)

		evt := &syscallEvent{}
		evt.perfEventHeader = perfEvtHeader
		evt.Params = make(map[string]interface{})

		paramLens := make([]uint16, perfEvtHeader.Nparams)

		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, paramLens)
		if err != nil {
			logger.Error(err, "error reading param length data")
			continue
		}

		data = data[binary.Size(paramLens):]

		switch perfEvtHeader.Type {
		case 307: // openat exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]

				switch i {
				case 0:
					evt.Params["fd"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["dirfd"] = binary.LittleEndian.Uint64(rawParams)
				case 2:
					// ignore the last byte \u000
					evt.Params["name"] = string(rawParams[:paramLens[i]-1])
				case 3:
					evt.Params["flags"] = binary.LittleEndian.Uint32(rawParams)
				case 4:
					evt.Params["mode"] = binary.LittleEndian.Uint32(rawParams)
				case 5:
					evt.Params["dev"] = binary.LittleEndian.Uint32(rawParams)
				}
				data = data[paramLens[i]:]
			}
		case 292: // execve_enter
			evt.Params["name"] = string(data[:paramLens[0]-1])

			proc, err := procfs.NewProc(int(evt.Tid))
			if err != nil {
				logger.Error(err, "failed to get Process info", "pid", evt.Tid)
				continue
			}

			var procName, executable string
			if proc.PID > 0 {
				procName, err = proc.Comm()
				if err != nil {
					logger.Error(err, "failed to get Process name", "pid", evt.Tid)
				}
				executable, err = proc.Executable()
				if err != nil {
					logger.Error(err, "failed to get Process executable", "pid", evt.Tid)
				}
			}

			process := Process{
				Name:       procName,
				Executable: executable,
			}

			processMap[evt.Tid] = process
		}

		queryToOPA(evt)
	}
}
