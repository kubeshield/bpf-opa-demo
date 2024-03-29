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

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os/user"
	"sync"

	"github.com/the-redback/go-oneliners"
	v1 "k8s.io/api/core/v1"
	"kubeshield.dev/bpf-opa-demo/rules"
)

type opaRequest struct {
	Input *opaInput `json:"input"`
}

type opaInput struct {
	Event   *syscallEvent `json:"event"`
	Process *Process      `json:"process"`
}

type syscallEvent struct {
	*perfEventHeader
	Name   string                 `json:"name"`
	Params map[string]interface{} `json:"params"`
}

type Process struct {
	Name        string     `json:"name"`
	Pid         uint64     `json:"pid"`
	Ppid        uint64     `json:"ppid"`
	Executable  string     `json:"executable"`
	Args        []string   `json:"args"`
	Command     string     `json:"command"`
	Cgroup      []string   `json:"cgroup"`
	Parent      *Process   `json:"parent"`
	User        *user.User `json:"user"`
	ContainerID string     `json:"containerID"`
	Pod         *v1.Pod    `json:"pod"`
}

func querySyscallEventToOPA(wg *sync.WaitGroup, opaQueryCh chan *syscallEvent) {
	defer wg.Done()
	for evt := range opaQueryCh {
		processMapLock.RLock()
		proc := processMap[evt.Tid]
		parent := processMap[proc.Ppid]
		processMapLock.RUnlock()

		if proc.Pid == 0 {
			p, _ := procDirFS.Proc(int(evt.Tid))
			proc = getProcessInfo(p)
		}
		if parent.Pid == 0 {
			p, _ := procDirFS.Proc(int(proc.Ppid))
			parent = getProcessInfo(p)
		}

		proc.Parent = &parent

		evt.Name = getSyscallName(int(evt.Type))

		req := &opaRequest{
			Input: &opaInput{
				Event:   evt,
				Process: &proc,
			},
		}

		reqBytes, err := json.Marshal(req)
		if err != nil {
			logger.Error(err, "failed to marshal event")
			continue
		}

		reqReader := bytes.NewReader(reqBytes)

		out, err := callOpaAPI("POST", "http://localhost:8181/v1/data/rules", reqReader)
		if err != nil {
			logger.Error(err, "failed to call rules api")
			continue
		}

		// output is empty, {"result":{}}
		if len(out) <= 13 {
			continue
		}

		var opaResult map[string]interface{}
		err = json.Unmarshal(out, &opaResult)
		if err != nil {
			logger.Error(err, "failed to unmarshall queryToOPA response")
			continue
		}

		oneliners.PrettyJson(opaResult["result"])
	}
}

func loadRules() error {
	err := loadFile("macros")
	if err != nil {
		logger.Error(err, "failed to laod macros file")
		return err
	}

	err = loadFile("rules")
	if err != nil {
		logger.Error(err, "failed to laod rules file")
		return err
	}

	return nil
}

func loadFile(name string) error {
	filename := fmt.Sprintf("%s.rego", name)

	log := logger.WithValues("filename", filename)

	b, err := rules.Asset(filename)
	if err != nil {
		log.Error(err, "failed to read file")
		return err
	}

	r := bytes.NewReader(b)
	url := fmt.Sprintf("http://localhost:8181/v1/policies/%s", name)

	_, err = callOpaAPI("PUT", url, r)
	if err != nil {
		log.Error(err, "failed to read macros file")
		return err
	}

	return nil
}

func callOpaAPI(method, url string, body io.Reader) ([]byte, error) {
	log := logger.WithValues("url", url, "method", method)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		log.Error(err, "failed create request")
		return nil, err
	}

	c := http.Client{}

	resp, err := c.Do(req)
	if err != nil {
		log.Error(err, "failed to do http request")
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err, "failed to read response body")
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		err = errors.New("request is not successfull")
		logger.Error(err, string(b), "code", resp.StatusCode)
		return nil, err
	}

	return b, nil
}
