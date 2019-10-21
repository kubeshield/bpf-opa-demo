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
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/the-redback/go-oneliners"
)

var (
	processMapLock sync.RWMutex
	processMap     = map[uint64]Process{}
)

func parseRawSyscallData(parseCh chan *rawSyscallData, opaQueryCh chan *syscallEvent) {
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
		case 293: // execve_exit
			var proc Process

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
					proc.Executable = evt.Params["exe"].(string)
				case 13:
					evt.Params["comm"] = string(rawParams[:paramLens[i]-1])
					proc.Command = evt.Params["comm"].(string)
				case 2:
					evt.Params["args"] = convertToStringSlice(rawParams)
					proc.Args = evt.Params["args"].([]string)
				case 4:
					evt.Params["pid"] = binary.LittleEndian.Uint64(rawParams)
					proc.Pid = evt.Params["pid"].(uint64)
				case 5:
					evt.Params["ppid"] = binary.LittleEndian.Uint64(rawParams)
					proc.Ppid = evt.Params["ppid"].(uint64)
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
					proc.Cgroup = evt.Params["cgroup"].([]string)
				}
				data = data[paramLens[i]:]
			}
			processMapLock.Lock()
			processMap[evt.Tid] = proc
			processMapLock.Unlock()
			// oneliners.PrettyJson(proc)

		case 186: // procexit
			go func() {
				// wait 1 second before deleting process from map
				time.Sleep(time.Second)
				processMapLock.Lock()
				delete(processMap, evt.Tid)
				processMapLock.Unlock()
			}()

		case 175: // rename exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["oldpath"] = string(rawParams[:paramLens[i]-1])
				case 2:
					evt.Params["newpath"] = string(rawParams[:paramLens[i]-1])
				}
			}
		case 177: // renameat exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["olddirfd"] = binary.LittleEndian.Uint64(rawParams)
				case 2:
					evt.Params["oldpath"] = string(rawParams[:paramLens[i]-1])
				case 3:
					evt.Params["newdirfd"] = binary.LittleEndian.Uint64(rawParams)
				case 4:
					evt.Params["newpath"] = string(rawParams[:paramLens[i]-1])
				}
			}
		case 277: // mkdir exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["pathname"] = string(rawParams[:paramLens[i]-1])
				}
			}
			// oneliners.PrettyJson(evt)
		case 305: // mkdirat exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["dirfd"] = binary.LittleEndian.Uint64(rawParams)
				case 2:
					evt.Params["pathname"] = string(rawParams[:paramLens[i]-1])
				case 3:
					evt.Params["mode"] = binary.LittleEndian.Uint32(rawParams)
				}
			}
			// oneliners.PrettyJson(evt)
		case 279: // rmdir exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["pathname"] = string(rawParams[:paramLens[i]-1])
				}
			}
			// oneliners.PrettyJson(evt)
		case 301: // unlink exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["pathname"] = string(rawParams[:paramLens[i]-1])
				}
			}
			// oneliners.PrettyJson(evt)
		case 303: // unlinkat exit
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["dirfd"] = binary.LittleEndian.Uint64(rawParams)
				case 2:
					evt.Params["pathname"] = string(rawParams[:paramLens[i]-1])
				case 3:
					evt.Params["mode"] = binary.LittleEndian.Uint32(rawParams)
				}
			}
			// oneliners.PrettyJson(evt)
		case 179: //symlink
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["target"] = string(rawParams[:paramLens[i]-1])
				case 2:
					evt.Params["linkpath"] = string(rawParams[:paramLens[i]-1])
				}
			}
			// oneliners.PrettyJson(evt)
		case 181: //symlinkat
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["target"] = string(rawParams[:paramLens[i]-1])
				case 2:
					evt.Params["newdirfd"] = binary.LittleEndian.Uint64(rawParams)
				case 3:
					evt.Params["linkpath"] = string(rawParams[:paramLens[i]-1])
				}
			}
			// oneliners.PrettyJson(evt)
		case 315: //chmod
			spew.Dump(paramLens)
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["filename"] = string(rawParams[:paramLens[i]-1])
				case 2:
					evt.Params["mode"] = binary.LittleEndian.Uint32(rawParams)
				}
			}
			oneliners.PrettyJson(evt)
		case 317: //fchmod
			spew.Dump(paramLens)
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["fd"] = binary.LittleEndian.Uint64(rawParams)
				case 2:
					evt.Params["mode"] = binary.LittleEndian.Uint32(rawParams)
				}
			}
			oneliners.PrettyJson(evt)
		case 313: //fchmodat
			spew.Dump(paramLens)
			for i := 0; i < int(perfEvtHeader.Nparams); i++ {
				if paramLens[i] == 0 {
					continue
				}
				rawParams := make([]byte, paramLens[i])
				rawParams = data[:paramLens[i]]
				data = data[paramLens[i]:]

				switch i {
				case 0:
					evt.Params["ret"] = binary.LittleEndian.Uint64(rawParams)
				case 1:
					evt.Params["dfd"] = binary.LittleEndian.Uint64(rawParams)
				case 2:
					evt.Params["filename"] = string(rawParams[:paramLens[i]-1])
				case 3:
					evt.Params["mode"] = binary.LittleEndian.Uint32(rawParams)
				}
			}
			oneliners.PrettyJson(evt)
		}

		opaQueryCh <- evt
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
