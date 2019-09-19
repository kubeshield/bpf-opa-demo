package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/davecgh/go-spew/spew"
)

type opaInput struct {
	Input *syscallEvent `json:"input"`
}
type syscallEvent struct {
	Event  *perfEventHeader       `json:"event"`
	Params map[string]interface{} `json:"params"`
}

func queryToOPA(opaInputCh chan *syscallEvent) {
	for {
		evt := <-opaInputCh
		input := &opaInput{Input: evt}

		b, err := json.Marshal(input)
		if err != nil {
			logger.Error(err, "failed to marshal event")
			continue
		}

		opaInput := bytes.NewReader(b)

		out, err := callOpaAPI("POST", "http://localhost:8181/v1/data/rules", opaInput)
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

		spew.Dump(opaResult["result"])
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
		logger.Error(err, "response", string(b), "code", resp.StatusCode)
		return nil, err
	}

	return b, nil
}
