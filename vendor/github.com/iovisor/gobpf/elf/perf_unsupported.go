// +build !linux

package elf

type PerfMap struct{}

func InitPerfMap(b *Module, mapName string, receiverChan chan []byte) (*PerfMap, error) {
	return nil, errNotSupported
}

func (pm *PerfMap) SetTimestampFunc(timestamp func(*[]byte) uint64) {}

func (pm *PerfMap) PollStart() {}

func (pm *PerfMap) PollStop() {}
