package main

type opaInput struct {
	Input *syscallEvent `json:"input"`
}
type syscallEvent struct {
	Event  *perfEventHeader       `json:"event"`
	Params map[string]interface{} `json:"params"`
}
