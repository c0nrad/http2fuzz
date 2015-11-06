// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package config

import (
	"flag"
	"time"
)

const (
	ModeClient = "client"
	ModeServer = "server"
)

const (
	ReplayWriteFilename = "./replay.json"
	ReplayReadFilename  = "./replay.json"
)

var RestartDelay time.Duration
var FuzzDelay time.Duration
var Target string
var FuzzMode string
var ReplayMode bool

var Port string
var Interface string

var MaxRestartAttempts = 3
var KeyboardDelay = false

func init() {
	restartMillisecond := 10
	fuzzDelay := 100

	flag.StringVar(&Target, "target", "", "HTTP2 server to fuzz in host:port format")
	flag.IntVar(&restartMillisecond, "restart-delay", restartMillisecond, "number a milliseconds to wait between broken connections")
	flag.IntVar(&fuzzDelay, "fuzz-delay", fuzzDelay, "number of milliseconds to wait between each request per strategy")

	flag.StringVar(&Port, "port", "8000", "port to listen from")
	flag.StringVar(&Interface, "listen", "0.0.0.0", "interface to listen from")

	// flag.BoolVar(&ReplayMode, "replay", false, "replay frames from replay.json")
	flag.Parse()

	RestartDelay = time.Duration(restartMillisecond) * time.Millisecond
	FuzzDelay = time.Duration(fuzzDelay) * time.Millisecond

	if Target != "" {
		FuzzMode = ModeClient
	} else {
		FuzzMode = ModeServer
	}
}

func IsTLS() bool {
	return true
}
