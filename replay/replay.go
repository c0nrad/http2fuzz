// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package replay

import "github.com/c0nrad/http2fuzz/util"

import "os"

var ReplayWriteFile *os.File

func init() {
	ReplayWriteFile = OpenWriteFile("replay.json")
}

type ReplayHandler struct {
	ReplayFile *os.File
}

func OpenWriteFile(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	return f
}

func TruncateFile() {
	ReplayWriteFile.Truncate(0)
	ReplayWriteFile.Seek(0, 0)
}

func WriteToReplayFile(data []byte) {
	data = append(data, '\n')
	_, err := ReplayWriteFile.Write(data)
	if err != nil {
		panic(err)
	}
	ReplayWriteFile.Sync()
}

func SaveRawFrame(frameType, flags uint8, streamID uint32, payload []byte) {
	frame := map[string]interface{}{
		"FrameMethod": "RawFrame",
		"FrameType":   frameType,
		"Flags":       flags,
		"StreamID":    streamID,
		"Payload":     util.ToBase64(payload),
	}

	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

// func RunReplay(c *fuzzer.Connection, frames []string) {
// 	for _, frameJSON := range frames {
// 		frame := util.FromJSON([]byte(frameJSON))

// 		if c.Err != nil {
// 			fmt.Println("Connection Error", c.Err, "restarting connection")
// 			c = fuzzer.NewConnection(Target, c.IsTLS, c.IsPreface, c.IsSendSettings)
// 		}

// 		switch frame["FrameMethod"] {
// 		case "RawFrame":
// 			fmt.Println(frame)
// 			frameType := uint8(frame["FrameType"].(float64))
// 			flags := uint8(frame["Flags"].(float64))
// 			streamID := uint32(frame["StreamID"].(float64))
// 			payload := util.FromBase64(frame["Payload"].(string))
// 			c.WriteRawFrame(frameType, flags, streamID, payload)
// 			time.Sleep(time.Second * 1)
// 		}
// 	}
// 	fmt.Println("ALL DONE")
// }
