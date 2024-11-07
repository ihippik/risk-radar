package radar

import "time"

type Event struct {
	EventType string
	EventTime time.Time
	Data      map[string]any
}

type coreEvent struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
}
