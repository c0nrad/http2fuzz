// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package fuzzer

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/c0nrad/http2fuzz/config"
	"github.com/c0nrad/http2fuzz/replay"
)

func FuzzConnection(conn net.Conn) {
	restartFuzzer := false
	isTLS := true
	choice := 2 //rand.Intn(9)

	// time.Sleep(time.Millisecond * 1000)
	switch choice {
	case -1:
		fuzzer := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer.PingFuzzer()
	case 0:
		fuzzer := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer.PingFuzzer()
		go fuzzer.DataFuzzer()
		go fuzzer.HeaderFuzzer()
	case 1:
		fuzzer := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer.RawFrameFuzzer()
	case 2:
		fuzzer2 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer2.PriorityFuzzer()
		go fuzzer2.PingFuzzer()
		go fuzzer2.HeaderFuzzer()
	case 3:
		fuzzer3 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer3.PriorityFuzzer()
		go fuzzer3.PingFuzzer()
		go fuzzer3.HeaderFuzzer()
		go fuzzer3.WindowUpdateFuzzer()
	case 4:
		fuzzer4 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer4.PriorityFuzzer()
		go fuzzer4.PingFuzzer()
		go fuzzer4.HeaderFuzzer()
		go fuzzer4.ResetFuzzer()
	case 5:
		fuzzer5 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer5.SettingsFuzzer()
		go fuzzer5.HeaderFuzzer()
	case 6:
		fuzzer6 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer6.DataFuzzer()
		go fuzzer6.HeaderFuzzer()
	case 7:
		fuzzer7 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer7.ContinuationFuzzer()
		go fuzzer7.HeaderFuzzer()
	case 8:
		fuzzer8 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer8.PushPromiseFuzzer()
		go fuzzer8.HeaderFuzzer()
	case 9:
		fuzzer9 := NewFuzzer(NewServerConnection(conn, isTLS), restartFuzzer)
		go fuzzer9.RawTCPFuzzer()
	}
}

func Server() {
	host := config.Interface + ":" + config.Port
	cert, err := tls.LoadX509KeyPair("./certs/localhost1437319773023.pem", "./certs/localhost1437319773023.key")
	if err != nil {
		panic(err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "h2-14"}}
	listener, err := tls.Listen("tcp", host, &config)
	fmt.Println("Listening on https://" + host)
	fmt.Println("setInterval(function() { $.get('https://" + host + "') }, 750)")

	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()

		if err != nil {
			panic(err)
		}
		proto := conn.(*tls.Conn).ConnectionState().NegotiatedProtocol
		log.Println("Negotiated proto", proto)

		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		replay.TruncateFile()
		FuzzConnection(conn)
	}
}
