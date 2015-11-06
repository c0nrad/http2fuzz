// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package fuzzer

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/c0nrad/http2fuzz/config"
	"github.com/c0nrad/http2fuzz/util"

	"github.com/bradfitz/http2"
)

type Fuzzer struct {
	Mu   *sync.Mutex
	Conn *Connection

	RestartConnection bool
	Alive             bool
	RestartAttempts   int
}

func NewFuzzer(c *Connection, restart bool) *Fuzzer {
	return &Fuzzer{Conn: c, Mu: new(sync.Mutex), RestartConnection: restart, Alive: true, RestartAttempts: 0}
}

func (fuzzer *Fuzzer) CheckConnection() {
	for fuzzer.Conn.Err != nil {

		if !fuzzer.RestartConnection {
			fuzzer.Alive = false
			return
		}

		time.Sleep(config.RestartDelay)
		fuzzer.Mu.Lock()
		if fuzzer.Conn.Err != nil {
			fuzzer.Conn = NewConnection(config.Target, fuzzer.Conn.IsTLS, fuzzer.Conn.IsPreface, fuzzer.Conn.IsSendSettings)
		}
		fuzzer.Mu.Unlock()
		fuzzer.RestartAttempts += 1
		if fuzzer.RestartAttempts > config.MaxRestartAttempts {
			fuzzer.Alive = false
			return
		}
	}
	fuzzer.RestartAttempts = 0
}

func (fuzzer *Fuzzer) RawTCPFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		payloadLength := int32(rand.Intn(10000))
		payload := make([]byte, payloadLength)
		crand.Read(payload)

		fuzzer.Mu.Lock()
		if _, err := io.WriteString(fuzzer.Conn.Raw, string(payload)); err != nil {
			fuzzer.Conn.handleError(err)
		}
		fuzzer.Mu.Unlock()

		if config.KeyboardDelay {
			util.WaitForEnter()
		} else {
			time.Sleep(config.FuzzDelay)
		}

		fuzzer.CheckConnection()
	}

	fmt.Println("Stopping RawTCPFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) ContinuationFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		streamId := uint32(rand.Int31())
		endStream := rand.Int31()%2 == 0

		payloadLength := int32(rand.Intn(10000))
		payload := make([]byte, payloadLength)
		crand.Read(payload)

		fuzzer.Mu.Lock()
		fuzzer.Conn.WriteContinuationFrame(streamId, endStream, payload)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()
	}

	fmt.Println("Stopping ContinuationFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) PushPromiseFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		payloadLength := int32(rand.Intn(10000))
		payload := make([]byte, payloadLength)
		crand.Read(payload)

		promise := http2.PushPromiseParam{
			StreamID:      uint32(rand.Int31()),
			PromiseID:     uint32(rand.Int31()),
			BlockFragment: payload,
			EndHeaders:    rand.Int31()%2 == 0,
			PadLength:     uint8(rand.Intn(256)),
		}

		fuzzer.Mu.Lock()
		fuzzer.Conn.WritePushPromiseFrame(promise)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()

	}

	fmt.Println("Stopping PushPromiseFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) DataFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		streamId := uint32(rand.Int31())
		endStream := rand.Int31()%2 == 0

		payloadLength := int32(rand.Intn(10000))
		payload := make([]byte, payloadLength)
		crand.Read(payload)

		fuzzer.Mu.Lock()
		fuzzer.Conn.WriteDataFrame(streamId, endStream, payload)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()

	}

	fmt.Println("Stopping DataFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) RawFrameFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		frameType := uint8(9)
		for frameType == 9 {
			frameType = uint8(rand.Intn(15))
		}

		flags := uint8(rand.Intn(256))
		streamId := uint32(rand.Int31())

		payloadLength := int32(rand.Intn(100))
		payload := make([]byte, payloadLength)
		crand.Read(payload)

		fuzzer.Mu.Lock()
		fuzzer.Conn.WriteRawFrame(frameType, flags, streamId, payload)
		fuzzer.Mu.Unlock()
		fmt.Printf("%d, %d, %d, FromBase64(%s)\n", frameType, flags, streamId, util.ToBase64(payload))

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()
	}
	fmt.Println("Stopping RawFrameFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) WindowUpdateFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		streamId := uint32(rand.Int31())
		incr := uint32(rand.Int31())

		fuzzer.Mu.Lock()
		fuzzer.Conn.WriteWindowUpdateFrame(streamId, incr)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()
	}
	fmt.Println("Stopping WindowUpdate Fuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) ResetFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		streamId := uint32(rand.Int31())
		errorCode := uint32(rand.Int31())

		fuzzer.Mu.Lock()
		fuzzer.Conn.WriteResetFrame(streamId, errorCode)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()
	}
	fmt.Println("Stopping ResetFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) PingFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		data := [8]byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))}
		fmt.Println("SENDING DATA", data)
		fuzzer.Mu.Lock()
		fuzzer.Conn.SendPing(data)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()
	}
	fmt.Println("Stopping PingFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) PriorityFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		streamDep := uint32(rand.Int31())
		streamId := uint32(rand.Int31())
		weight := uint8(rand.Intn(256))
		exclusive := rand.Int31()%2 == 0

		fuzzer.Mu.Lock()
		fuzzer.Conn.WritePriorityFrame(streamId, streamDep, weight, exclusive)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()
	}
	fmt.Println("Stopping PriorityFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) HeaderFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		headers := make(map[string]string)
		numberHeaders := rand.Intn(5)
		for i := 0; i < numberHeaders; i++ {
			headers[util.RandomHeader()] = util.RandomHeaderValue()
		}
		fuzzer.Mu.Lock()
		fuzzer.Conn.cmdHeaders(headers)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()

	}
	fmt.Println("Stopping HeaderFuzzer:", fuzzer.Conn.Err)
}

func (fuzzer *Fuzzer) SettingsFuzzer() {
	fuzzer.CheckConnection()

	for fuzzer.Alive {
		settings := []http2.Setting{}
		numberSettings := rand.Intn(5)
		for i := 0; i < numberSettings; i++ {
			setting := http2.Setting{
				ID:  randomSettingID(),
				Val: uint32(rand.Int31()),
			}
			settings = append(settings, setting)
		}

		fuzzer.Mu.Lock()
		fuzzer.Conn.WriteSettingsFrame(settings)
		fuzzer.Mu.Unlock()

		time.Sleep(config.FuzzDelay)
		fuzzer.CheckConnection()

	}
	fmt.Println("Stopping SettingsFuzzer:", fuzzer.Conn.Err)
}

func randomSettingID() http2.SettingID {
	return http2.SettingID(rand.Intn(6))
}
