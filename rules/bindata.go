// Package rules Code generated by go-bindata. (@generated) DO NOT EDIT.
// sources:
// macros.rego
// macros_test.rego
// rules.rego
// rules_test.rego
package rules

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// ModTime return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _macrosRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x5a\x6d\x8f\xdc\x36\x92\xfe\x3c\xfa\x15\x84\x1a\x07\x78\x80\x51\xb7\xed\x4b\xee\x0e\x41\x9c\x43\x36\x36\x02\x03\x8b\x78\x61\x3b\xbb\x58\x0c\x1a\x02\x9b\x64\x4b\x44\x4b\xa4\x4c\x52\xdd\xd3\x13\xf8\xbf\x2f\xaa\x48\xea\xad\xa5\x79\x49\xfc\x65\x9a\x2c\xb2\x1e\x56\x15\x8b\xc5\x62\x69\x1a\xca\x0e\xb4\x10\xa4\xa6\xcc\x68\x9b\x24\xab\x64\x45\x74\x23\x14\x11\x47\xa1\x9c\x4d\x56\x09\xf4\xf2\x93\x91\x4e\x90\x3f\x92\x2b\xec\xe1\x58\x72\x25\x6d\xde\x0f\x26\x57\x52\x35\xad\x5b\xe3\xd8\xba\xa1\x86\xd6\xf6\x36\xdd\xf3\x74\x4b\x7e\x7a\x43\x5e\x26\x5f\x13\x8f\x64\x04\xe5\x4b\x40\x30\xf6\x54\x1c\x66\x04\x5d\x16\xc9\x8f\x3e\x8e\x35\x81\x1a\x4e\x57\xb4\x16\xe4\x0d\x49\x71\x34\xed\xd6\xc5\xc1\x85\xb9\x38\xc1\x9e\x2d\xa3\x55\x65\x6f\xf3\x6d\xc7\x14\x69\xe4\x87\x37\xe4\x96\xa4\x40\x4b\x6f\xfc\x2f\x75\x29\xd9\x26\xc9\xc8\x96\x00\x6f\x74\xab\xf8\x8b\x17\x97\x0a\xac\xf7\x15\x2d\x6c\xf6\x72\xfd\xea\x9a\x6c\xc8\x87\xfc\x5f\x1f\x3f\xfc\xf6\xf7\x7f\x5f\x93\xff\x22\xaf\xc9\x4f\xde\x40\x43\x7b\x3e\x0b\xeb\xe3\xdb\x45\xac\xde\x48\x4f\x46\xfb\xe5\xe3\xbb\x9f\x3f\x0f\xc1\x74\xee\x4c\xab\x58\x0e\xf3\x72\x2b\xdc\xb3\xd0\x3e\x7f\xfc\xfd\xb7\x5f\x46\xa2\x45\x79\xc1\xaa\xaf\x92\x68\x09\xe8\xbd\x4e\xc2\xea\x04\x7a\xdf\x25\x81\x1b\x7b\xaf\xbf\xff\x9f\xc4\xfb\xb9\x15\xca\x4a\x27\x8f\x82\xec\x65\x25\xc0\xd7\x3b\x4a\x8e\x14\xdc\xae\xe4\x2a\xdd\x08\xc7\x36\xb6\xa4\x5c\x9f\xd2\x9b\xae\xdf\x72\x2d\x8c\xed\x09\x0d\xad\xd7\x4c\xab\xfd\x60\x8a\x60\xad\x91\xee\xbc\x69\x4e\x5f\x5a\x5a\x49\x77\xf6\x13\x92\xed\x60\x25\x2e\x8d\x60\x4e\x9b\x73\x0e\x5e\x14\x5d\x64\x03\xfe\x01\x20\xf1\xd7\x13\x8c\xd6\xae\x6b\x6c\xd0\x73\x50\x93\x52\x54\x15\x01\x6c\x59\x80\x1e\x3b\x6a\xcb\xdc\x77\x51\x93\x21\xf2\x1a\x06\x0d\xe2\x62\x33\x6f\x8c\x86\x39\x3d\xa1\x94\x16\xe4\xe9\x09\x95\x2e\xa4\x1a\x75\x75\x8b\x62\xac\x71\xdb\x02\x58\xc4\x21\xdb\x84\x3d\xb0\x3c\xeb\x56\xef\x61\x07\x88\xc3\xc5\x5d\x3f\x97\xd9\x92\x4b\x63\x01\xfc\xfe\x01\xf0\x7b\x5b\x0a\x75\x44\x8e\xfb\xa1\x5e\xf7\x1d\xd0\x7d\xbf\xea\x7d\x58\x16\xac\x88\x16\xbc\x80\xbd\x85\xbf\x5b\xf2\x07\xc1\x03\xfe\xc3\x1b\x32\x6b\xd8\xdb\x7c\x4b\xbe\x3e\x15\x61\xce\x34\xcf\x02\x98\x53\xdf\x03\x5c\x6c\x7b\xe7\x4c\xe8\x9e\xbd\x39\xb0\x1f\xdc\xe0\x72\xb7\x46\x5c\xcc\x96\xfd\x8e\x75\x14\x6f\xc3\x59\xbb\x3d\x6e\xb3\x25\x75\x1f\xb5\x55\x54\x73\xc4\x19\x8f\x8f\x1c\xcb\x7d\x6f\xcb\xee\x74\xe0\x7d\x36\x3c\x22\xdd\x79\xf7\xc1\xf9\x42\x10\x88\x4b\x51\x86\x85\x5d\xc9\xb7\xc9\x95\x50\xdc\x9e\xa4\x2b\x5f\x00\xf9\x06\xa5\xbe\xee\x43\xfe\x2c\x2a\x34\xc8\x0c\xe8\xf8\xb6\x58\x64\xcd\xa5\xb2\x92\x0f\x62\xc6\x8b\x25\x5b\xdc\xe6\x5b\x94\xa5\x8f\x0e\x8d\xd1\x4c\x58\x8c\x72\xc8\xb3\x93\x8a\x0e\xac\x46\x6d\x09\x5b\xbc\x0b\xbf\xcc\xff\x1c\xfc\x8f\xff\xeb\x02\xf1\xde\xff\x70\x1a\x6c\x2c\x6d\x10\x39\x2c\x41\xfe\x20\x3e\x9c\x87\x7e\xbc\x1e\xc7\xeb\x86\xcd\x04\x01\x99\xd1\x2a\x59\x25\x6d\xc3\xa9\x13\x39\xf4\x82\x46\xdd\xf5\x1e\x52\x0c\xeb\xa8\x71\x43\x9b\x07\x97\x34\x5a\xa5\xa8\x2e\x4e\x40\x04\x47\x77\xc0\x6d\x1b\x7a\x52\x82\x47\xd1\xe2\xb5\x1d\x25\x13\x77\x82\xb5\x8e\xee\xaa\x70\xd5\x23\x5f\x1a\x0d\xa7\xc4\x69\x68\xb6\x31\xd4\x52\xbe\x00\x90\x47\xd1\x61\x44\x57\x0b\x3b\x1f\x3d\x28\xee\x68\x74\xb3\xb9\x44\x05\xc6\x52\x74\x8b\xf9\xbd\xe7\xd2\x5c\x03\xce\xaa\x47\xf5\x06\x22\x60\x21\xd2\x4d\x44\xcf\x9c\x31\x1e\xf0\x4f\xd1\x0b\x79\x14\x6a\xb0\x46\x44\xf6\xb3\xd1\xa2\x63\x98\x7e\x30\x6a\x5c\x6b\x2e\xf7\xe7\x64\x95\x18\x1c\x9c\x26\x3f\x9e\x0a\x0e\xe4\x5b\x3e\x01\x32\x9d\x55\x66\x6c\x3a\x01\x0a\x67\xa5\x3e\x70\x69\xa6\xe8\x48\x04\x70\x6c\x78\x6c\x6c\x2e\x40\x8f\x41\x02\xb2\x11\xb5\x3e\x5e\x0a\x5e\x07\xe8\x56\x55\x52\x1d\xfa\x56\xd4\x00\x98\x16\x35\x18\x21\x46\x0d\xd0\x52\x98\x05\xa1\x86\xc9\xd7\x11\x09\x58\xa2\x51\xfb\x3c\x5d\xd1\x42\xd4\x90\x83\xc6\x83\x04\x96\x6e\xea\xf1\x79\x4e\xae\x52\x0e\x99\x08\x49\x4d\x53\x87\x9f\x83\xc0\x5b\xf5\xdc\x22\xe1\x7f\xbf\xcf\xec\xd9\x3a\x51\x67\x78\xec\x70\x4e\x69\x6b\x26\x8c\xe3\xd9\x49\x9b\x03\x6e\x91\x6d\x77\x96\x19\xd9\x38\xa9\x55\x56\xd3\xf4\x26\x21\x84\xc0\xce\x35\xfa\x4b\x2b\xfc\x35\xed\xa1\x6d\x68\x7e\x09\x6b\x64\x78\x28\x63\x1b\x4f\x73\x06\xc2\x47\x12\x17\xbb\xb6\xc8\x78\x5b\x37\x11\x94\xee\x8c\xcb\x28\xc3\xa5\x2c\x3d\x06\x3c\xbe\xcb\xad\xf3\xf2\xd5\x92\x19\x1d\xd5\x2a\x55\xce\x4a\xc1\x0e\x01\x8f\xef\x20\xab\xc2\xf8\x69\x19\x6d\xf2\x0b\x8b\x90\xb4\x31\x7a\x27\x60\x40\xaa\xbd\x06\xb6\x8e\x70\x14\x46\xee\xcf\x33\xa4\x78\x61\x4e\xc8\x61\x33\x30\xf8\xc1\x42\x10\x11\x06\xf1\x60\x12\xf6\x86\xa2\xf8\x8d\x7f\x9c\x67\x56\x8f\xa7\x32\xa7\x96\x56\x2e\xab\xa5\x92\x5a\x61\x1c\xe2\x62\x77\xe9\x1e\xcd\xa1\xc0\x28\xde\x1c\x8a\xac\x31\xc2\x6f\x51\xdb\x91\x3a\x8a\xe9\x48\x5c\x1e\x85\xc1\x9d\xa0\x4d\xfc\xc9\x0a\x11\x9b\xd2\xb5\x5c\xc4\xcd\xdc\x43\x28\x15\x8a\x7b\xeb\x09\xa9\xac\x9f\xc6\x79\x06\x5c\xe0\x40\x56\x76\x20\xb4\x75\x3a\x43\x87\xa7\x91\x84\xde\x1a\x1c\xa3\x71\x59\x25\xad\x63\x25\x55\x85\xb0\xfe\xe0\x51\x07\xf0\x82\x67\x6d\x53\x98\x0e\x87\xf3\x29\xb4\xd7\xa2\xeb\x51\x56\x0a\xf4\x94\xb0\x87\x79\x5d\xd4\xae\xb7\xf0\x4e\xaa\x2d\xd8\x75\x27\x15\x18\xea\xd2\xfa\x4f\x62\x1b\xda\xfb\x09\x6c\xa0\xe4\x4e\xaa\xe8\xa7\xfe\x1a\xcc\x68\xe5\x84\x51\x14\xde\x08\x20\x7d\x21\xf0\xd8\x36\xb2\x09\x3f\xff\x8d\xe7\x93\x2a\x91\xb5\x4e\x56\x76\xdd\xe8\x60\xe2\x9e\x0f\x4d\xc5\x4a\xb1\xcf\x58\x25\x85\x0a\x36\x39\x80\xdf\x46\x51\x61\xdd\x10\x8d\x3a\x19\xbb\x10\x33\xbc\xea\x56\xe4\xf3\x87\xb7\x1f\x7e\x20\xd2\x12\xe9\x08\xd3\x06\x6e\x88\xff\x7f\xf0\x3e\x9d\x57\xda\x2f\x06\x31\xcd\x2b\x4a\xc2\x86\x69\xe3\xef\x8c\xd8\x19\xe5\xa2\x56\xb7\x86\x09\xbb\x06\x37\xf0\xc1\xb6\x9b\x36\x4d\x00\x7d\x4a\x40\x1b\xb7\x19\x32\xad\x79\x97\xc0\x9e\xdb\x7a\x8d\xfc\x6b\x8e\x27\x98\x32\x10\x3d\xef\x20\xa5\xcf\xb7\x26\xd9\xdd\x54\xb0\x90\x60\x2d\x30\xcf\x5f\xd8\xf3\x52\xc7\x54\x0d\x73\x9c\x1e\xe9\x3c\x4d\x7e\x66\x96\x4a\xbe\xce\x72\x85\x1b\x38\xfc\x4e\x39\x92\x19\xf2\x70\x87\xf7\xf2\x8e\x34\xd4\x95\x18\x4d\xf6\xda\x10\xba\xb3\xba\x6a\x9d\x40\xea\x28\x01\x98\x79\xb5\x47\xce\x91\xc5\x16\x12\x53\xf0\xc1\xc1\x10\x3c\x5c\x25\x26\x1f\x5d\x2a\xbf\xf3\x4f\xb5\x8d\x8d\x8d\xd6\x9a\xcd\xb0\x8d\x03\xb0\x8b\x81\x73\xd9\xf8\x11\x7a\x28\x40\x73\x76\x25\xa6\x9e\xbe\x91\x9b\x56\x29\xa9\x8a\xbc\x10\x2e\x6f\x64\x73\x19\x61\x99\xae\x6b\xaa\x38\x04\x59\xcf\x92\x4e\x67\x50\x53\xd8\xdb\x97\x5b\x98\x51\x08\x97\x35\xba\x59\x37\x67\x88\xc2\x93\x25\x6a\x9b\xeb\x7a\x26\x86\x3f\x6b\x85\xcd\x91\x9a\x4d\x25\x77\x9b\x13\xa5\x85\x12\x6e\xd3\xa5\x9d\x5c\xb3\x83\x30\xd0\xf4\xad\xee\x28\x7b\xc3\x7a\x22\x46\x76\x6c\xe1\x49\x58\x89\x3b\xd1\xc9\x17\xd8\x2c\xf5\x39\xcd\xea\x62\xd7\x3b\x81\x6b\x5e\x49\x05\xb9\xb8\xb8\x13\xa4\x93\x28\xac\x70\x1d\xfd\x2a\xb9\x5a\x8d\xf9\x1a\xf4\x2f\x69\xc9\x8b\x20\xc2\x4d\x10\xfa\xfa\x3a\x59\x41\x2a\x7f\xae\x21\xb9\x9a\x66\x61\x81\x8c\xc1\xcf\x37\x43\x05\xcd\x17\xa8\xf2\x40\x5c\xc8\xc3\xa6\xa0\x21\x1a\x45\xb2\xa3\x06\xb6\x5e\xaa\x7c\x5c\x09\x9a\xa2\x05\x5f\xf7\xd3\x01\x76\x5c\x37\xf2\xa8\x4f\x01\x7d\x28\xf5\x5e\x5c\xf0\x86\x2c\x56\x8f\xa2\x73\xc3\x5d\xea\xfc\x32\x39\xd3\xcd\x79\x9a\x0b\x19\x7b\x56\xf8\xa4\xb7\x0c\xef\x13\xbb\x77\xf8\xcb\x59\x13\x73\xd9\x11\x7b\x4c\x38\xe0\xaa\x9a\x4f\x72\x96\x16\xec\x52\x6a\x4c\xe1\x9d\xce\x4b\xc9\xb9\x50\x9d\x05\x42\xe6\x7b\xc5\xe0\xe9\x25\x95\x9d\x53\x5b\x89\x13\x84\x15\x38\xf3\x6b\x7c\xe7\xf9\xac\x3d\x20\xf5\xef\x1c\x08\x7d\x30\xf2\x30\x5a\x1f\xa1\x22\x5c\x70\x9d\x89\x64\xa3\xda\xf6\xa4\xae\xdc\xe1\xc7\x67\x28\x00\x5d\x29\xed\xc8\x70\x47\xc5\x1d\xab\x5a\x2e\xf8\x85\xa4\x60\x91\x30\x38\x1d\x1b\xd4\x31\xb0\xc6\xb7\x66\xd4\x5a\xaa\xb8\xa1\xb0\x31\x4f\x42\x27\x6f\x96\xa3\xe0\xf2\xaa\xd1\x75\x58\x59\x6b\x3e\x3d\x75\x48\x04\x07\xd9\x4f\x5a\xe1\xf0\x7d\xca\xdf\x7f\xfa\xf5\xfd\x5b\xac\xc4\xbe\x7c\xfd\x1d\x59\xbd\x78\x45\x7e\xfc\x91\xbc\x7a\x79\x8d\x43\xbf\xfb\xa1\xd7\x2f\xbf\xfb\xbf\x6e\xe8\xd5\xb5\xaf\x1c\x08\xd7\xca\x47\xaa\xd4\xb5\xe6\x22\x16\x82\x03\xdc\xb0\x10\xec\x51\x8a\xe7\xa2\xfc\x3a\x87\xd2\x4a\x9e\x6b\x33\xc0\xeb\xc8\x8f\x4d\x29\x70\x8a\x37\xdf\x42\xf4\x19\x9b\x36\xc6\x1e\xac\x8a\x84\xb2\xe7\x28\xe9\x99\x16\x63\xef\xc7\xdd\xbd\xb4\x25\x96\xf8\x2f\x88\xb1\x0f\x3b\xc3\x45\x25\x20\x2c\x0e\x57\x99\x7a\xf7\xb4\x2e\x7f\xe1\xdf\x33\x32\x06\x77\x89\x4f\xf3\x29\xfc\x24\x05\x19\x8d\x0f\x72\x90\x0b\xbe\x07\xc3\x00\x1e\xda\x65\x59\xfe\x0c\xa6\xae\xb8\x0f\x2d\xdf\x16\xb6\x8f\x31\xcb\xb8\x09\xa7\x8e\xe6\xa1\x32\x30\xbe\x9e\x6d\x69\x04\xf7\x55\x8c\xbd\xf5\xbf\xe2\xf5\x1e\xab\xdf\x49\x52\xe9\xd9\xaa\x27\x5e\xbc\x1a\x5f\x3a\x1b\x2e\x8e\xd8\x86\xf9\x30\x7d\x94\x4a\x9f\x6d\x98\x46\x5b\x87\xa5\x5c\xbc\x00\x04\x6b\x0d\x3e\x34\x0e\xc2\xa8\x48\x8d\x6f\xf8\xd6\x0a\x13\x69\xf0\x14\x8c\xed\x8a\x5a\x17\xdb\x90\x56\x47\x60\x9f\xa9\x86\x5e\x7d\xb6\x5f\xaa\xf5\xb0\xc3\xd7\x51\xb8\x7e\x66\x5f\xe8\xbc\xa8\x53\x4d\x14\x1e\x67\xde\x23\xd6\x49\xce\xde\x8d\x75\x39\x9f\x4f\x45\x56\xce\xb4\xd6\x09\x0e\xcc\x05\x24\x3b\xb2\xa6\x05\x22\xac\xae\x5e\x84\x6d\x15\x66\x8d\xd4\xf5\x20\xb5\x8e\xf0\x24\xb5\x4d\xd5\xaa\xc3\x66\x5f\xb5\x42\x39\x9e\x95\x82\xa5\x3e\x6b\x29\x8c\x68\xa6\x97\x2d\xd0\x40\x77\x11\x1b\x7b\x6c\x80\xfe\x38\x3d\xa4\x7c\x0f\x26\x83\x23\xdc\x18\x39\x04\x35\xac\xcc\x1b\x23\x8f\x70\x7d\x1d\xc4\x9c\x5b\x8e\xb2\xc6\x7c\x7b\x43\xd2\xbf\xbd\xfb\xf5\xfd\x6f\xe4\x1f\x1f\xdf\xff\xf3\xe7\xcf\xef\xf0\xfe\xfb\x4b\x40\x1f\x3f\xfd\xfc\xed\xc0\xde\x7e\x4b\xb0\x77\xbf\x8c\xb0\x3a\x30\x6a\xed\x49\x1b\xfe\x24\x24\x98\x3c\x92\xe4\x39\xcc\xd6\x96\x7f\x9a\x17\x8e\x9c\x17\x5b\x09\x77\xd2\xe6\x90\x3b\xad\x2f\xaa\xf6\x3e\x89\x53\xcc\x17\xc8\x54\x4d\x7d\x16\xe7\x0b\x1e\x8e\x35\xbe\xbe\x46\x52\x67\x4b\x6a\x30\x69\x56\x9d\xef\x8d\x70\x17\x2a\x4a\xbd\x03\xce\x4a\x11\x1c\x31\x51\xec\xb2\x2a\x3e\x2d\x4a\x29\x96\x26\x57\x8a\xe5\x70\x80\x72\x01\x37\x28\x43\xed\x46\x94\x27\x99\x26\x13\x68\x98\x3f\xc3\xc9\x82\x49\x19\x75\x4f\x91\x98\x3a\x94\x99\xba\x9c\x9a\x22\x8f\xf0\xb9\xb8\x13\xb8\xfe\x0c\x3d\xe4\xc8\xe4\x71\x51\x32\x5b\x66\xe2\x4e\xb0\xa0\xcb\x5f\xc3\xfa\x56\x40\x82\x7c\x0b\x14\xf6\x4d\x50\xb2\xaa\xa5\xbd\x62\x09\xad\x2a\x7d\x12\x3c\xe7\xe2\x38\xf9\x3a\x0f\xb7\x9d\x6a\xab\xaa\xbb\xfa\xac\xe3\xa1\x44\x10\x7a\xe1\xe3\x72\xec\x0a\x63\xfc\x47\x7a\xe8\x1b\xaa\xb8\xae\xbb\xe1\x76\xd2\x67\x5a\x59\x1d\x3e\x9b\x42\xff\x50\xdb\x22\x4d\xb6\x09\x88\x81\xaf\x01\xa9\xd5\xf4\x54\xee\xaa\x83\xe4\xfd\x17\x0e\x10\x59\x32\x84\x08\x9f\xb8\x84\x2a\xa4\xf2\x05\xf6\x82\x4b\x7b\xf0\x17\xfb\x08\x72\xd1\x3b\xfb\x23\x39\x2b\xc2\xf0\x43\xe2\xa5\xc9\xfa\x4f\x90\x17\x63\x81\x11\xe2\xce\xb8\x62\xe7\xab\x6a\xf8\xc9\xb7\xa3\xa5\x21\x34\x9e\xf8\x88\xe4\xff\x47\x02\xeb\x91\x3d\x9d\x6c\xbb\xbd\x5b\x00\x27\xa9\x6d\xfd\xd7\x06\xae\x63\x5a\x11\xf2\x05\xa5\xbb\xef\xf5\xad\x92\x77\x39\x2b\x0f\xcd\x09\xab\x15\xa6\xed\x15\x9c\xc1\x7d\xc0\x6e\xcb\x5c\xc1\x06\x71\x42\x43\x8d\x50\x6e\x90\x38\x39\x51\x73\x5f\x79\xc0\x26\xd6\x5c\xa5\xf2\x15\x69\x2e\x8e\xb1\xef\xbf\xa6\xb4\x2a\x6b\x20\x93\x19\x26\x52\xf1\x0b\x63\x90\xdf\x2f\xf0\x2c\x35\x3c\xcb\x73\xb4\xf9\x7d\x0e\x15\x8e\xe0\xf4\xdb\xe8\xe5\xe3\xbe\x5f\x65\x1e\x1d\x38\xe0\xd1\xfb\xf0\x5e\x8c\xa6\x3d\xaa\x32\xce\x5e\x61\x9e\x86\x2d\x60\xec\x72\xb2\x9e\xf4\x84\x7a\x94\x77\x50\x92\x7d\x4a\xaf\x9f\xc1\x87\x37\x2f\xe5\x9c\x64\x6f\x9f\xc5\xd7\x79\x05\xc9\xb2\xa3\x30\x56\xe2\x37\xe9\x8e\x1f\x74\xdf\x9d\xf3\x2f\x2d\xad\xce\xf6\x82\x6c\xdb\x1a\x1d\x9d\xe5\x3e\x11\xf7\x5f\x8d\xa7\xb3\xce\x6d\x7d\x41\xf3\x75\xc4\x0b\x72\xa1\x75\x51\x89\x9c\x32\xa6\x5b\xe5\x6c\xce\xa9\xa8\xb5\x4a\xbe\x26\xff\x09\x00\x00\xff\xff\x1e\x14\xe0\xb1\xf1\x27\x00\x00")

func macrosRegoBytes() ([]byte, error) {
	return bindataRead(
		_macrosRego,
		"macros.rego",
	)
}

func macrosRego() (*asset, error) {
	bytes, err := macrosRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "macros.rego", size: 10225, mode: os.FileMode(420), modTime: time.Unix(1573722179, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _macros_testRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xc4\x98\xcf\x6f\xdc\x2a\x10\xc7\xcf\xf5\x5f\x81\xbc\x97\x56\x4a\xd6\xd9\x24\xbd\x44\xca\xed\xdd\x7b\x79\xb7\xaa\x42\xac\x8d\xbd\x68\x6d\x40\xc0\x26\x4d\xaa\xfd\xdf\x9f\xc0\xf8\x07\xfe\xb1\x6b\x7b\x71\x9f\xaa\x4a\xde\x81\xcc\xf7\xc3\xcc\x18\x06\x73\x14\x1f\x51\x86\x41\x81\x62\xc1\x64\x10\x6c\x82\x0d\x50\x58\x2a\xc0\x38\xa6\xf0\x5d\x10\x85\x83\x4d\xa0\x2d\xb0\xb1\x40\x8a\x33\x98\x26\xe0\x4f\xf0\x85\xb2\xf6\x54\xf0\x4e\xd4\x01\x10\xca\x4f\x0a\x20\x09\xfe\x80\x10\xbf\x61\xaa\x42\xf0\xa2\x9f\x29\x2a\x70\xf8\x02\x42\x3d\x3f\xbc\x03\x21\x47\x02\x15\xd2\x0e\xa6\x89\x7e\xb8\xdf\xdd\x81\x30\xcd\x51\x66\xcc\x3b\x70\xd6\xff\x82\x73\x0f\x80\x33\x09\xd3\x04\xbe\x0b\x46\x33\xa8\xe7\xaf\xc0\x32\x0f\x25\x66\x42\xd4\x24\x6b\x51\x3c\xd6\x14\x9d\x44\x09\x8c\x12\x27\x4f\xda\x30\x94\x26\x6d\xff\x0b\x59\x32\xf2\x97\x93\xe4\x85\xc4\x01\x79\xb8\x02\xd2\x4f\x91\x7f\x86\xdd\x58\x86\x8c\x53\x27\x45\xc6\x62\x1e\x6b\x1e\x63\x9a\x00\x04\x2a\xa2\xde\x7a\x1b\xa7\x48\x2d\x76\x8b\xd4\x98\xe3\x14\xe5\x12\x3b\x69\x9c\xe3\xdb\xbc\x11\x61\x2f\x3e\x44\xc2\x5e\x11\xb7\x6d\x26\x67\xf0\xa1\x92\x6d\x0f\x5d\x16\x76\x93\x35\x52\x26\x7d\xa5\x9d\x56\xba\x55\x65\x77\x4d\xe5\xd1\xd7\x7a\x1e\xaf\x29\x3d\xf9\x58\xcf\xd3\x35\x95\x67\x5f\xeb\x79\xbe\xa6\xf4\xdd\xc7\x7a\xbe\x0f\xbc\xa8\x95\x4f\xe7\xd8\x73\x8c\x23\xa5\x38\x61\xab\x9f\x55\x8b\x2d\xad\x9d\x37\xad\x91\x8a\x6c\x69\x3d\xb6\x03\xbb\x58\x67\xa4\x1e\x5b\x3a\x4f\x5e\x74\x46\x2a\xb2\xa5\xd3\x2b\xc9\xc5\x5a\xcf\xc3\xd5\x22\x0f\x38\xcf\x21\x17\x2c\xc6\x52\xb6\x0a\xc6\xb1\xbb\x9b\x66\x77\xb4\x4f\x63\x07\xba\x9b\xe7\x1b\x29\xc2\xce\x7a\x5d\x99\x3d\x92\x07\x1b\xd8\x65\x0a\xda\xc1\x65\x89\xcf\x1b\x15\x3e\x1b\x81\xce\xf1\x58\xfa\x8b\x19\x4d\x49\x06\x53\x92\x63\xe9\x9c\x95\xfd\x61\xb3\x5c\x11\xd7\x67\x5c\x7f\xc6\x8c\x3c\xd7\x80\xdb\xd2\x6b\x38\xd0\x49\x8c\x20\xc0\x03\x91\x8a\x89\x8f\x35\x40\x2a\xdf\x13\x71\x3e\xd7\x08\xc8\xe7\x8c\x78\x60\x15\xeb\x92\xd0\x3f\x3c\x63\x44\x58\xc5\x91\x75\x3d\x03\x26\x96\x87\x9c\x65\x84\xae\x41\x13\xcb\xc3\xd6\x38\x9f\xc1\x63\xdf\x1f\xdf\x28\xd5\x6b\xb5\x70\x83\x5a\x77\xd3\xb8\x79\xe3\xd3\x5e\xfb\xbb\xc6\x89\x27\x48\x61\x18\x0b\x46\x6d\x10\xab\xe5\xf5\x47\x34\xc2\x80\x75\x79\xe3\xdf\xa9\x04\xc1\x68\x54\xfa\xd4\x33\x2f\xde\xdb\x46\x08\x21\x65\xed\x4b\x65\x15\xb3\xff\x15\xfa\x61\x12\xb4\xfe\x6f\x6c\x09\x11\x2b\x63\x6b\x0c\xc3\x7d\x35\xca\x4d\x99\x48\x85\x44\x09\xa8\xd0\xbe\xaa\x10\xc7\xa8\xa1\x5d\xc3\x24\x56\xfc\x1b\xc7\x6f\x7a\x2f\xba\xeb\x16\xae\x1e\x39\x29\xb4\xcf\x4b\x6c\xeb\xd5\x79\x47\x1c\x3d\x13\xc2\xd2\x5d\x15\xc0\x05\x3c\xf5\xbd\xcd\x0f\x4f\x2b\x38\x0b\x81\x26\x07\x88\x32\xd5\x61\x6a\xe5\xaf\xdc\x18\x11\x4d\x40\x42\x44\xbd\x83\xd9\x13\x06\x00\x60\x26\x68\x49\xf0\xf2\x6a\x9e\xc7\xe0\xda\x7b\xa8\xc3\x19\x9d\xa4\x88\xf6\x84\x46\x6d\x08\x70\x76\x9d\xbf\x0e\xcc\xd3\xa0\x86\x26\x21\x02\xc7\xb6\x07\xa8\xfe\x0a\x12\x2a\x49\x82\x9b\xb1\xaf\xb5\x83\xf0\x9b\x37\xc6\xf3\x30\x80\xce\xd8\x4a\x10\x3d\x80\x26\x55\x05\x4b\x48\xfa\x51\xa5\xa8\xfc\xa5\xeb\xc7\x3e\x4d\xfb\x44\x20\x70\xf9\xd8\x5a\xdd\x52\x4f\x45\x42\x44\xff\xdc\x28\x8e\x09\x11\x35\xe4\xd1\xee\x5a\xe5\xc3\x34\xc7\x66\xae\x4b\xb8\xd8\x0d\x1a\x38\xd9\x04\x2f\xcc\x19\x59\x57\x7b\x6d\xd0\x12\xcd\x8f\xa9\xe7\xa7\x44\xb9\xba\x2f\x08\x25\xcc\xfd\x5e\x74\xa3\xdb\x84\xa6\x3e\xdd\x71\xc1\xf6\x58\x3b\x21\x34\x65\xfd\xa0\x34\xdf\xa9\x29\xca\x70\x81\xa9\x02\x9d\xae\xc6\xce\x80\xcd\x8c\x76\x07\x72\x61\xf4\x0a\x61\x67\xb7\x4a\xf8\x31\x73\xd6\xfd\x97\x74\x39\xe1\x33\x64\xf5\x0e\xe0\x4d\xba\x75\xf3\x6c\x12\x82\x62\x73\x23\x14\x98\x33\x49\x14\x13\xa4\xb9\xb1\x0d\x0c\x69\xa6\x21\xf3\x84\x3d\xa8\x5b\xcd\xec\x24\x62\x2c\xb7\x39\xb1\x5d\x61\x13\x92\x11\x5d\x1d\x0b\x3f\xda\x75\x27\x7a\x55\xd3\x8f\x9e\x69\xd4\x10\x57\x51\x7b\xd1\xdb\x24\x72\x39\xba\x3b\xf0\x60\x4e\x06\x86\x9a\x1d\x75\x21\x27\x47\xea\x30\x93\xf5\x12\x8b\xce\x93\x3f\x9e\xb1\x18\x95\x9f\x87\x6a\x81\xfa\xbc\xea\xda\x35\x51\xcf\xe6\xa1\x8b\x75\xea\x77\xd2\x6d\xa1\x4b\x31\x72\x57\xf0\x0d\x3b\x8d\xf5\x61\x02\xab\x75\x03\xb5\x9b\x15\x69\x4d\xc6\x17\x45\x74\x4e\xae\x07\xdb\x95\x2e\xd2\xd2\x37\x63\x30\x7c\x4d\xff\x33\x27\x70\x43\x3d\xcb\xaa\x98\x8d\xf1\x36\xd4\x29\x21\x1d\x7b\xb9\xf7\xc4\xdc\x43\xab\x77\xda\xfe\x84\x4a\x9c\xcc\x6b\x62\x7f\x2f\xfa\xce\xb2\xef\x7d\xe8\xa9\xbc\x3b\x9f\x77\x6f\x91\x18\x5b\x15\xff\x50\x07\x46\x01\x27\xbc\xee\x75\x8c\x05\x8a\x13\xa5\x84\x66\x30\xc3\x0a\x72\xc2\x4d\xbf\x31\x3c\x72\xe5\xc0\x8f\x59\x51\x20\x9a\x94\x8d\x86\xf1\xa0\xe3\x8f\x44\xa6\xaf\x00\x3f\x41\x98\x61\x75\xcf\x19\xdf\xf2\x8f\x10\xfc\x72\xba\x90\x51\x10\xd3\x81\xac\x02\x73\xc0\x39\x6f\x30\x7a\x61\x2a\x24\x60\x85\x1c\x89\x54\x21\x21\x2b\xe4\x40\xa0\xec\xc0\x8d\x68\xd1\x1b\x12\x51\x4e\xf6\xd1\x3b\x42\x19\xc5\x2a\xba\x1c\xae\x52\xd4\x2d\xa0\x55\xb8\xca\xca\xea\x87\x2c\x61\xf1\x11\x8b\x56\x27\xbd\x01\xff\xfe\xf8\xe7\xc7\x4b\xb0\x31\xb8\xf8\x37\xae\x41\xca\xa9\x50\x22\xf3\x95\x62\xf3\x65\x6c\x6c\x06\x69\xf9\x67\x13\x23\xb8\x29\x3f\xd2\x48\xed\xff\xab\xf1\xbf\xb5\x9e\xb7\x71\x91\xe4\x84\xe2\x3b\xd3\xb8\x82\xda\x83\x75\xff\x2d\xd8\x7c\x71\xe7\x73\x24\x30\x55\x5b\x8b\x02\x5e\x6d\x18\xaa\xee\xf8\x27\xfc\x15\x6c\xce\xc1\x7f\x01\x00\x00\xff\xff\x27\x0c\x8d\x2f\x1a\x23\x00\x00")

func macros_testRegoBytes() ([]byte, error) {
	return bindataRead(
		_macros_testRego,
		"macros_test.rego",
	)
}

func macros_testRego() (*asset, error) {
	bytes, err := macros_testRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "macros_test.rego", size: 8986, mode: os.FileMode(420), modTime: time.Unix(1573722179, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _rulesRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x9c\x96\x51\x8b\xe3\x36\x10\xc7\x9f\xad\x4f\x21\x36\x2f\x77\xdc\x11\x53\x4a\x4b\x59\xd8\xa7\x6b\xdf\xca\x1d\xb4\xf7\x76\x1c\x42\x96\x26\xf6\x34\xb6\x64\xa4\x51\xd2\x50\xfc\xdd\x8b\x64\x67\x37\x89\x65\xa7\xe9\xc3\x82\x37\xfa\x6b\xac\x19\xcd\xfc\xfe\xee\xa5\xda\xcb\x1a\xb8\x0b\x2d\x78\xc6\xb0\xeb\xad\x23\xae\x25\xc9\x6d\x27\x95\xb3\x7e\xeb\xc1\x78\x24\x3c\x80\xd8\x61\xd4\x64\x24\xb6\x07\x23\x1c\x48\xbd\xb8\x78\x74\x48\x90\x5b\x45\x2f\x7c\x03\x6d\x2b\x7a\x67\x15\xf8\xe5\xf0\xa3\x4a\x59\xb3\xc3\x7a\xf9\x24\xa1\xd7\x92\x40\x28\x67\xcd\xa4\xcd\xa6\x44\xd2\x51\x12\x91\xac\x72\x82\x74\x5c\xe1\xa0\xb7\x1e\xc9\xba\x53\x4e\x33\x55\x4e\x74\xd2\xc8\x1a\x3a\x30\xb4\x96\x43\x85\x46\x68\x74\xd9\x40\x27\x6a\xac\x11\x2e\x18\x83\xa6\x16\x35\x90\xe8\xb1\xcf\x29\x95\x83\x98\x9d\x3f\x75\x2d\x9a\x7d\x36\xb3\x71\x49\x90\x74\x31\x0e\x1a\x71\x7d\x7d\xd9\x3d\xbd\x3c\x1a\xd0\x6b\xa7\x77\xd0\xd9\x58\x56\xdb\x9f\x92\x6c\x41\x64\x64\x07\x82\xac\x68\x50\x6b\x30\x8b\x2f\xec\xf6\x1a\xdd\x59\xa4\xd1\x81\x5a\xaa\xf1\x94\xf0\x9d\x78\xaa\xe9\x6c\xb6\xf5\x62\x73\x01\x05\xd4\xc2\xba\xf8\x54\x63\x56\xa6\xa1\x85\x58\xd6\xd4\x61\x0d\xfa\xa5\xd3\x4c\x09\xde\xd5\xc5\x67\x11\x4b\x76\x80\xb5\xa2\x4a\x15\x57\x44\x6b\x57\xfa\xd9\x0a\x72\xc1\x28\xb1\x6b\x65\x1d\x33\xc8\x0f\xa8\x74\xaa\x11\xbd\xc3\x43\x2c\xd6\x1e\xb2\x87\x3a\xab\xa4\xf7\x47\xeb\xb2\x75\x30\x40\x47\xeb\xf6\x82\xac\x6d\x97\xaf\xd9\xa8\xb5\xa4\x8c\x92\xab\x73\x90\x66\x79\xbc\xd6\xfc\x55\x1c\xc6\x55\xb4\xe6\x6e\x18\xd9\xb6\xf6\x08\x5a\xc4\x4d\x8b\x15\x4c\x4d\xc3\x46\x84\x5c\x93\x8c\xbf\x70\x34\x7d\x20\xfe\x0f\x2b\xde\x08\x56\xa4\xdf\xb6\x70\x00\x43\xdb\x5e\x3a\xd9\xf9\x6f\x4f\xf1\xde\x9f\xbe\xf3\x17\x7e\x13\xe2\x9b\xf8\xce\x06\xc6\x3a\xab\x71\x77\xba\x42\x54\x70\x63\x0e\x51\x36\x7b\xd1\x48\xc3\xc2\x58\xe2\x33\xfe\x15\x4b\xb4\x1b\x18\x8b\x07\xfc\xef\x6f\x19\xd3\x79\xf8\x25\x5e\x35\xa0\x43\x3b\x41\xf4\x2f\x5b\x5d\x15\x2a\x03\xd8\xbb\x7b\xae\x71\x3b\x30\x36\x05\x39\x13\xf4\x8d\xb3\x97\xbb\x66\x0c\x4e\xa9\xac\x50\x77\x60\x6c\xdc\x53\xa1\x91\xee\x14\xc9\x72\x19\xef\x4c\xe0\xd9\x15\xac\x84\xe4\x9c\xf3\x24\xc9\x23\x7a\x60\xec\x15\xc9\x7e\x04\xaf\x3d\x80\x5b\x6b\xb4\x1b\x84\x17\x77\x81\x3d\x30\xd6\xca\x60\x54\x23\x26\x08\xc7\x5f\x47\x12\xa7\x39\xc5\x74\x0f\x24\xd1\x80\x4b\xc5\xbe\xa1\x79\xb1\xe1\x5f\xbf\xfc\xfa\xe5\x39\x3e\xbc\x09\xcb\x52\x35\xa0\xf6\x9e\xe3\x8e\xa3\xf1\xa8\xe1\x6d\x91\x15\x73\xdc\x5f\xa4\x7a\x01\xe3\x88\xd5\x57\x7e\x5f\x66\x99\xb7\x82\xe1\x91\x10\x0b\x26\xf1\x50\x8c\x8c\x7d\xc4\x66\x05\x9a\xd9\x82\xa8\x90\xae\x76\x26\x4b\x29\x72\x06\x32\x30\x36\x19\x86\x75\x22\x67\x09\x97\x71\xb2\xd6\x32\x3c\x10\x20\xeb\x39\x09\x05\xc9\x5e\xaa\xd0\xee\x45\xf2\x9b\x9d\xb3\x9d\xd0\xe8\xf7\x57\x93\x77\xdb\x0c\x23\xdc\xa6\x7f\xb7\xca\x76\x9d\x34\x9a\xbf\xf0\x8c\x65\x4d\x6c\x53\x2d\x48\x97\x4c\x4a\x2a\xc2\x03\x12\x66\xc8\x39\x4d\xd3\xcc\xd1\x8a\x99\x7f\x15\x9b\xd8\x8d\xac\xd8\xc4\xb1\x22\x17\x3c\x81\x8e\x1b\xea\x38\x57\xd8\xc9\x7a\xba\xa2\x5b\x4b\x8b\xb5\x3a\x7b\xd7\x55\x86\x73\xf3\x1b\xfe\xc7\xf6\xb3\x2b\x0e\x8c\xfd\x3e\x4e\xdb\x9f\xc1\xf7\xa8\xd0\x06\x2f\x3e\x4f\xbe\xf8\xd5\xda\xf6\x62\x73\x84\xc3\x6d\x81\x13\x30\xe6\x36\x3a\x30\xf6\x19\x28\x5a\xe3\x1f\xe3\x68\x7d\xb2\x1a\xc4\x6f\x7f\x83\x0a\x91\xdf\x97\x27\xba\xb0\xd7\xe1\x81\x4d\xf2\x8a\x83\x1b\xfe\xee\x08\xbc\x93\x27\x6e\x00\x34\x27\xcb\xa5\xd6\xf1\x0f\xe3\x4e\xd9\xf2\x69\xfa\x65\x2d\xd1\x78\xe2\x3b\xd9\x7a\xe0\x89\xb4\x78\x00\xff\x91\x7b\x80\x67\xb6\xe1\x0d\x51\xef\x9f\xcb\xb2\x0a\xb5\xdf\x8e\x18\xea\xa5\x8e\x1f\x0a\x65\xa8\x82\xa1\x50\x7e\xf0\x36\x38\x05\xa5\xdb\x37\xc1\x10\xb8\xf2\x43\x15\xea\xf2\x97\x9f\x7f\xf8\xe9\xc7\xf7\xec\xd3\x38\x7f\xa9\x17\x44\x05\xad\x3d\x46\xaf\x9e\x59\x83\x3f\x22\x35\xef\xa2\xea\x23\x7f\x2a\x35\x1c\x9e\xde\x4f\x7d\x35\x7d\x28\x24\x4c\x67\x3f\x0d\xd2\x4a\x3e\x48\x49\x74\x8a\x81\xa2\x62\xe1\x73\x61\x60\xff\x06\x00\x00\xff\xff\xa6\x70\x90\xd7\xff\x0c\x00\x00")

func rulesRegoBytes() ([]byte, error) {
	return bindataRead(
		_rulesRego,
		"rules.rego",
	)
}

func rulesRego() (*asset, error) {
	bytes, err := rulesRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "rules.rego", size: 3327, mode: os.FileMode(420), modTime: time.Unix(1573722179, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _rules_testRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xd4\x96\xdf\xae\xe2\x20\x10\xc6\xaf\xb7\x4f\x31\xc1\xdb\xcd\x71\x3d\x97\xbe\x0c\xa1\x65\x54\x56\x84\x06\xa8\xae\x31\xbe\xfb\x66\xfa\xbf\xda\x9e\xba\x5a\xf5\x6c\xbc\x21\x0c\x90\xef\x37\xdf\x8c\x9d\x54\x24\x5b\xb1\x46\x70\x99\x46\x1f\x45\xb3\x68\x06\x01\x7d\x00\x9b\xa2\xe1\x1e\x8d\x57\x41\xed\x91\xaf\x14\x85\x67\x11\xc5\x78\x4f\x0c\x4e\xd1\x8f\xbe\x2b\x70\x50\x61\x03\xca\xa4\x59\x00\xe1\xe1\x04\x0c\xf7\x68\x02\x83\x25\xad\x8d\xd8\x21\x5b\x02\xa3\x9b\xec\x27\xb0\x54\x38\xb1\xf3\xed\x20\x2c\x81\xcd\x31\x24\x73\xbf\x11\xd2\x1e\xe8\xd0\x4a\xd2\xee\x82\x56\x5a\xac\xf3\xd3\x0b\x38\xd3\x2f\x3a\x0f\xea\xe3\x8f\x0b\x14\xe1\xc9\x12\x57\x42\xfb\x3c\x91\xc6\xf6\xe7\x7f\x92\x64\x6e\x50\x6b\x3b\x3f\x58\xa7\xe5\xa8\xd4\xa6\x1c\x76\x56\xaa\xd5\x91\x7b\xba\xcd\x13\x6b\x56\x6a\x9d\x39\x11\x94\x35\xb9\xb4\xaa\x32\x46\x8e\x11\xdc\xd8\x91\x0b\xc6\x12\x71\x09\xa7\x21\xc0\x76\xe8\x23\x16\x7e\xe3\x92\x12\xac\xcd\xb5\x84\x4f\x38\x9f\xe9\x96\xb3\x09\xfa\xee\xb5\xbd\xda\x31\x38\xd7\xe6\x8c\x48\xe4\xc6\x06\x7e\x70\x2a\xd4\x66\xbd\x8d\xe9\xd7\x64\x4c\x45\x80\x1e\xfa\xce\x50\x74\xeb\x5f\x9d\x6a\x07\x5f\xc2\x46\xca\xee\xaf\xc0\xa6\xe7\x1c\x0a\xd9\x91\xd8\x69\xb5\xfe\x28\x01\x5e\x45\x5e\x63\xdb\xe2\xe6\x5a\xec\x97\x9e\x9b\x45\xa1\xca\xa4\x37\x71\xdc\xfe\x3f\x31\xc0\x71\xdd\x4a\xdf\xcf\x91\xcb\x46\xfa\xc2\x92\xbe\xfe\x79\x22\xd0\x60\xf7\xdc\x54\x5f\x4d\xf7\xf8\x64\x83\x32\xd3\xc8\x13\x67\x0d\xff\x6d\xe3\x7a\x7c\xb9\x8e\x10\x56\xcf\xee\x54\xb3\x0b\xbd\x38\x2f\xf2\x34\xf0\xc9\xfd\xec\x4e\x07\xd3\x2a\xc4\x3f\x98\xec\x91\x41\x3b\x7b\xc5\x09\x8a\x64\x41\xc4\xba\x10\x4b\xef\x06\x11\xb3\xab\xaf\x7f\x96\x4a\x11\x90\x97\xb3\x22\x77\x98\x5a\xaf\x82\x75\xc7\x2a\xa5\x83\x07\x48\xf7\x70\x70\x82\x04\x7b\x9b\xb9\x04\xfd\x87\x56\x75\xd9\xf4\x26\xf7\x2b\xf6\xba\x82\x1a\x07\x06\x35\xf3\xbd\xd0\x4a\xf2\xf2\xad\xaa\x1f\xfe\x07\x44\x99\x6e\xd7\x37\x32\xd6\x03\x4e\xbe\xf9\x12\xc8\x56\xdb\x8f\xc3\x5d\xb2\xf5\xff\x03\x14\x23\x5a\xac\x0c\x48\xe5\xaa\x4a\x2d\xb0\x62\x65\xb8\x54\x8e\xc8\xea\x0d\xe1\x8e\xf9\xde\x83\x30\xd4\xf4\xb1\x32\xf7\x1a\x95\xf7\x61\xda\xf1\xa9\x23\xb9\xf4\xa6\x99\x3d\xef\xd3\x5f\x3b\xfc\x1e\x88\x74\xbb\xa6\xf5\x63\x0c\x4f\xf5\xa0\xdd\x2d\x7f\x03\x00\x00\xff\xff\xf7\xeb\x64\xdc\x24\x0f\x00\x00")

func rules_testRegoBytes() ([]byte, error) {
	return bindataRead(
		_rules_testRego,
		"rules_test.rego",
	)
}

func rules_testRego() (*asset, error) {
	bytes, err := rules_testRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "rules_test.rego", size: 3876, mode: os.FileMode(420), modTime: time.Unix(1573722179, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"macros.rego":      macrosRego,
	"macros_test.rego": macros_testRego,
	"rules.rego":       rulesRego,
	"rules_test.rego":  rules_testRego,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"macros.rego":      {macrosRego, map[string]*bintree{}},
	"macros_test.rego": {macros_testRego, map[string]*bintree{}},
	"rules.rego":       {rulesRego, map[string]*bintree{}},
	"rules_test.rego":  {rules_testRego, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
