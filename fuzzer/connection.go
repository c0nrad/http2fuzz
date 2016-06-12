// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package fuzzer

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/c0nrad/http2fuzz/replay"

	"github.com/bradfitz/http2"
	"github.com/bradfitz/http2/hpack"
)

type Connection struct {
	Host           string
	IsTLS          bool
	IsPreface      bool
	IsSendSettings bool

	Raw net.Conn

	Framer *http2.Framer

	StreamID uint32
	HBuf     bytes.Buffer
	HEnc     *hpack.Encoder

	PeerSetting map[http2.SettingID]uint32
	HDec        *hpack.Decoder

	Err error
}

func NewConnection(host string, isTLS, sendPreface, sendSettingsInit bool) *Connection {
	conn := &Connection{
		Host:           host,
		IsTLS:          isTLS,
		IsPreface:      sendPreface,
		IsSendSettings: sendSettingsInit,
		PeerSetting:    make(map[http2.SettingID]uint32),
	}
	conn.HEnc = hpack.NewEncoder(&conn.HBuf)

	raw, err := Dial(host, isTLS)
	if err != nil {
		conn.handleError(err)
		return conn
	}
	fmt.Println(raw)
	conn.Raw = raw
	conn.SetupFramer()

	if sendPreface {
		conn.SendPreface()
	}

	if sendSettingsInit {
		conn.SendInitSettings()
	}

	go func() { conn.readFrames() }()

	return conn
}

func NewConnectionRaw(c net.Conn, tls bool) *Connection {
	conn := &Connection{
		Host:  "localhost",
		IsTLS: tls,
		Raw:   c,
	}
	conn.HEnc = hpack.NewEncoder(&conn.HBuf)
	conn.SetupFramer()
	conn.SendInitSettings()
	go func() { conn.readFrames() }()

	return conn
}

func NewServerConnection(c net.Conn, tls bool) *Connection {
	conn := &Connection{
		Host:           "localhost",
		IsTLS:          tls,
		Raw:            c,
		PeerSetting:    make(map[http2.SettingID]uint32),
		IsSendSettings: true,
	}
	conn.HEnc = hpack.NewEncoder(&conn.HBuf)
	conn.SetupFramer()

	conn.readPreface()
	conn.Framer.WriteSettings()
	conn.Framer.WriteSettingsAck()
	conn.Framer.WriteSettings()
	conn.Framer.WriteSettingsAck()

	go func() { conn.readFrames() }()

	return conn
}

func (conn *Connection) handleError(err error) error {
	if err != nil {
		log.Println(err)
		conn.Err = err
		if conn.Raw != nil {
			conn.Raw.Close()
		}
	}
	return err
}

func (conn *Connection) SetupFramer() {
	conn.Framer = http2.NewFramer(conn.Raw, conn.Raw)
	conn.Framer.AllowIllegalWrites = true
}

func (conn *Connection) SendInitSettings() {
	conn.Framer.WriteSettings()
	conn.Framer.WriteSettingsAck()
}

func (conn *Connection) readPreface() error {
	buffer := make([]byte, len(http2.ClientPreface))
	n, err := conn.Raw.Read(buffer)
	if err != nil {
		fmt.Println("Error reading preface", buffer)
		return conn.handleError(err)
	}
	fmt.Println("READ PREFACE", string(buffer[:n]))
	return nil
}

func (conn *Connection) SendPreface() error {
	if _, err := io.WriteString(conn.Raw, http2.ClientPreface); err != nil {
		return conn.handleError(err)
	}
	return nil
}

func settingByName(name string) (http2.SettingID, bool) {
	for _, sid := range [...]http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	} {
		if strings.EqualFold(sid.String(), name) {
			return sid, true
		}
	}
	return 0, false
}

func (conn *Connection) SendPing(data [8]byte) error {
	err := conn.Framer.WritePing(false, data)
	return conn.handleError(err)
}

func (conn *Connection) WriteSettingsFrame(settings []http2.Setting) error {
	fmt.Println("SettingsFrame", settings)
	err := conn.Framer.WriteSettings(settings...)
	return conn.handleError(err)
}

func (conn *Connection) WriteDataFrame(streamID uint32, endStream bool, data []byte) error {
	fmt.Println("DataFrame", streamID, endStream, data)
	err := conn.Framer.WriteData(streamID, endStream, data)
	return conn.handleError(err)
}

func (conn *Connection) WritePushPromiseFrame(promise http2.PushPromiseParam) error {
	fmt.Println("PushPromiseFrame", promise)
	err := conn.Framer.WritePushPromise(promise)
	return conn.handleError(err)
}

func (conn *Connection) WriteContinuationFrame(streamID uint32, endStream bool, data []byte) error {
	fmt.Println("ContinuationFrame", streamID, endStream, data)
	err := conn.Framer.WriteContinuation(streamID, endStream, data)
	return conn.handleError(err)
}

func (conn *Connection) WritePriorityFrame(streamId, streamDep uint32, weight uint8, exclusive bool) error {
	fmt.Println("PriorityFrame", streamId, streamDep, weight, exclusive)
	priorityParam := http2.PriorityParam{StreamDep: streamDep, Exclusive: exclusive, Weight: weight}
	err := conn.Framer.WritePriority(streamId, priorityParam)
	return conn.handleError(err)
}

func (conn *Connection) WriteResetFrame(streamId uint32, errorCode uint32) error {
	fmt.Println("ResetFrame", streamId, errorCode)
	err := conn.Framer.WriteRSTStream(streamId, http2.ErrCode(errorCode))
	return conn.handleError(err)
}

func (conn *Connection) WriteWindowUpdateFrame(streamId, incr uint32) error {
	fmt.Println("WindowUpdateFrame", streamId, incr)
	err := conn.Framer.WriteWindowUpdate(streamId, incr)
	return conn.handleError(err)
}

func (conn *Connection) WriteRawFrame(frameType, flags uint8, streamID uint32, payload []byte) error {
	err := conn.Framer.WriteRawFrame(http2.FrameType(frameType), http2.Flags(flags), streamID, payload)
	if err == nil {
		replay.SaveRawFrame(frameType, flags, streamID, payload)
	}

	return conn.handleError(err)
}

func (conn *Connection) cmdHeaders(headers map[string]string) error {

	hbf := conn.encodeHeaders(conn.Host, "GET", "", headers)

	if conn.StreamID == 0 {
		conn.StreamID = 1
	} else {
		conn.StreamID += 2
	}
	log.Printf("Opening Stream-ID %d:", conn.StreamID)

	if len(hbf) > 16<<10 {
		log.Printf("TODO")
		return nil
	}
	return conn.Framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      conn.StreamID,
		BlockFragment: hbf,
		EndStream:     true, // good enough for now
		EndHeaders:    true, // for now
	})
}

func (conn *Connection) readFrames() error {
	for {
		f, err := conn.Framer.ReadFrame()
		if err != nil {
			return fmt.Errorf("ReadFrame: %v", err)
		}
		log.Printf("Received: %v", f)
		switch f := f.(type) {
		case *http2.PingFrame:
			log.Printf("  Data = %q", f.Data)
		case *http2.SettingsFrame:
			f.ForeachSetting(func(s http2.Setting) error {
				log.Printf("  %v", s)
				conn.PeerSetting[s.ID] = s.Val
				return nil
			})
			// conn.cmdSettings([]string{"ACK"})
		case *http2.WindowUpdateFrame:
			log.Printf("  Window-Increment = %v\n", f.Increment)
		case *http2.GoAwayFrame:
			log.Printf("  Last-Stream-ID = %d; Error-Code = %v (%d)\n", f.LastStreamID, f.ErrCode, f.ErrCode)
			conn.handleError(fmt.Errorf("Received GoAwayFrame %v", f.ErrCode))
		case *http2.DataFrame:
			log.Printf("  %q", f.Data())
		case *http2.HeadersFrame:
			if f.HasPriority() {
				log.Printf("  PRIORITY = %v", f.Priority)
			}
			if conn.HDec == nil {
				// TODO: if the user uses h2i to send a SETTINGS frame advertising
				// something larger, we'll need to respect SETTINGS_HEADER_TABLE_SIZE
				// and stuff here instead of using the 4k default. But for now:
				tableSize := uint32(4 << 10)
				conn.HDec = hpack.NewDecoder(tableSize, conn.onNewHeaderField)
			}
			conn.HDec.Write(f.HeaderBlockFragment())
		}
	}
}

// called from readLoop
func (conn *Connection) onNewHeaderField(f hpack.HeaderField) {
	if f.Sensitive {
		log.Printf("  %s = %q (SENSITIVE)", f.Name, f.Value)
	}
	log.Printf("  %s = %q", f.Name, f.Value)
}

func (conn *Connection) encodeHeaders(host, method, path string, headers map[string]string) []byte {
	conn.HBuf.Reset()

	if host == "" {
		host = conn.Host
	}

	if path == "" {
		path = "/"
	}

	conn.writeHeader(":authority", host)
	conn.writeHeader(":method", method)
	conn.writeHeader(":path", path)

	if !conn.IsTLS {
		conn.writeHeader(":scheme", "http")
	} else {
		conn.writeHeader(":scheme", "https")
	}

	for k, v := range headers {
		lowKey := strings.ToLower(k)
		if lowKey == "host" {
			continue
		}
		conn.writeHeader(lowKey, v)
	}
	return conn.HBuf.Bytes()
}

func (conn *Connection) writeHeader(name, value string) {
	conn.HEnc.WriteField(hpack.HeaderField{Name: name, Value: value})
	log.Printf(" %s = %s", name, value)
}

func Dial(host string, isTLS bool) (net.Conn, error) {
	log.Printf("Connecting to %s ...", host)

	if isTLS {
		cfg := &tls.Config{
			ServerName:         host,
			NextProtos:         []string{"h2", "h2-14"},
			InsecureSkipVerify: true,
		}

		tc, err := tls.Dial("tcp", host, cfg)
		if err != nil {
			return nil, err
		}

		log.Printf("Connected to %v", tc.RemoteAddr())

		if err := tc.Handshake(); err != nil {
			return nil, err
		}

		state := tc.ConnectionState()
		if !state.NegotiatedProtocolIsMutual || state.NegotiatedProtocol == "" {
			return nil, errors.New("sever doesn't support http2")
		}
		log.Printf("Negotiated protocol %q", state.NegotiatedProtocol)

		return tc, nil
	} else {

		log.Printf("Connecting to %s ...", host)
		TCPConn, err := net.Dial("tcp", host)
		if err != nil {
			return nil, err
		}

		return TCPConn, nil
	}

}
