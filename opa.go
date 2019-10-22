package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/the-redback/go-oneliners"
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
	Name       string   `json:"name"`
	Pid        uint64   `json:"pid"`
	Ppid       uint64   `json:"ppid"`
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	Command    string   `json:"command"`
	Cgroup     []string `json:"cgroup"`
	Parent     *Process `json:"parent"`
}

// func queryToOPA(evt *syscallEvent) {
func querySyscallEventToOPA(opaQueryCh chan *syscallEvent) {
	for {
		evt := <-opaQueryCh

		if selfPid[int(evt.Tid)] {
			continue
		}

		processMapLock.RLock()
		proc := processMap[evt.Tid]
		parent := processMap[proc.Ppid]
		processMapLock.RUnlock()

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

		// spew.Dump(opaResult["result"])
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
	filename := fmt.Sprintf("./rules/%s.rego", name)

	log := logger.WithValues("filename", filename)

	b, err := ioutil.ReadFile(filename)
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
