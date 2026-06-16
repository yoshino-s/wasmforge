package c2

import "time"

// Beacon represents a C2 beacon/callback.
type Beacon struct {
	ID       string
	Hostname string
	Username string
	OS       string
	PID      int
}

// TaskResult holds the output of a C2 task/command.
type TaskResult struct {
	TaskID   int
	Output   string
	Error    string
	Success  bool
	Duration time.Duration
}

// Process represents a running process from a ps command.
type Process struct {
	PID  int
	PPID int
	Name string
	User string
}
