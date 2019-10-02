package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/procfs"
)

var (
	processMapLock sync.RWMutex
	processMap     = map[uint64]Process{}
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
				if paramLens[i] == 0 {
					continue
				}
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
				logger.V(6).Info("failed to get Process info", "pid", evt.Tid)
			}

			var procName, executable, containerID string
			var cmdline []string
			if proc.PID > 0 {
				procName, err = proc.Comm()
				if err != nil {
					logger.V(6).Info(errors.Wrap(err, "failed to get Process name").Error())
				}
				executable, err = proc.Executable()
				if err != nil {
					logger.V(6).Info(errors.Wrap(err, "failed to get Process executable").Error())
				}
				cmdline, err = proc.CmdLine()
				if err != nil {
					logger.V(6).Info(errors.Wrap(err, "failed to get Process cmdline").Error())
				}
				containerID, err = getContainerIDfromPID(proc.PID)
				if err != nil {
					logger.V(6).Info(errors.Wrap(err, "failed to get Process containerid").Error())
				}
			}

			process := Process{
				Name:        procName,
				Executable:  executable,
				Cmdline:     cmdline,
				ContainerID: containerID,
			}

			processMapLock.Lock()
			processMap[evt.Tid] = process
			processMapLock.Unlock()

		case 293: // execve_exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["exe"] = string(rawParams[:paramLens[i]-1])
				case 13:
					evt.Params["comm"] = string(rawParams[:paramLens[i]-1])
				case 2:
					evt.Params["args"] = convertToStringSlice(rawParams)
				case 4:
					evt.Params["pid"] = binary.LittleEndian.Uint64(rawParams)
				case 5:
					evt.Params["ppid"] = binary.LittleEndian.Uint64(rawParams)
				case 7:
					evt.Params["fdlimit"] = binary.LittleEndian.Uint64(rawParams)
				case 8:
					evt.Params["pgflt_maj"] = binary.LittleEndian.Uint64(rawParams)
				case 9:
					evt.Params["pgflt_min"] = binary.LittleEndian.Uint64(rawParams)
				case 10:
					evt.Params["vm_size"] = binary.LittleEndian.Uint32(rawParams)
				case 11:
					evt.Params["vm_rss"] = binary.LittleEndian.Uint32(rawParams)
				case 12:
					evt.Params["vm_swap"] = binary.LittleEndian.Uint32(rawParams)
				case 15:
					evt.Params["env"] = convertToStringSlice(rawParams)

				case 14:
					evt.Params["cgroup"] = convertToStringSlice(rawParams)
				}
				data = data[paramLens[i]:]
			}
		}

		queryToOPA(evt)
	}
}

// returns containerID from /proc/<pid>/cgroup file
// cgroup file content is in this format: 10:memory:/docker/<containerID>
func getContainerIDfromPID(pid int) (string, error) {
	cgroup := filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup")

	f, err := os.Open(cgroup)
	if err != nil {
		return "", err
	}

	s := bufio.NewScanner(f)
	for s.Scan() {
		str := s.Text()
		arr := strings.Split(str, "/")
		if len(arr) == 3 && arr[1] == "docker" {
			return arr[2], nil
		}
	}
	return "", nil
}

// converts raw syscall param of slice types into []string
func convertToStringSlice(rawParams []byte) []string {
	// last byte is \u000
	byteSlice := bytes.Split(rawParams, rawParams[len(rawParams)-1:])

	var res []string
	for _, b := range byteSlice {
		if len(b) > 0 {
			res = append(res, string(b))
		}
	}
	return res
}
