package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"k8s.io/klog/klogr"
)

type opaInput struct {
	Input *syscallEvent `json:"input"`
}
type syscallEvent struct {
	Event  *perfEventHeader       `json:"event"`
	Params map[string]interface{} `json:"params"`
}

func queryToOPA(opaInputCh chan *syscallEvent) {
	logger := klogr.New().WithName("[queryToOPA]")
	for {
		evt := <-opaInputCh
		input := &opaInput{Input: evt}

		b, err := json.Marshal(input)
		if err != nil {
			logger.Error(err, "failed to marshal event")
			continue
		}

		opaInput := bytes.NewReader(b)

		resp, err := http.Post("http://localhost:8181/v1/data/rules", "application/json", opaInput)
		if err != nil {
			logger.Error(err, "failed to create new requestt")
			continue
		}

		out, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Error(err, "failed to decode response body")
		}

		err = resp.Body.Close()
		if err != nil {
			logger.Error(err, "failed to close response body")
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

		spew.Dump(opaResult["result"])
	}
}
