// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package fuzzer

import "github.com/c0nrad/http2fuzz/config"

func Client() {
	target := config.Target
	tls := config.IsTLS()
	restartFuzzer := true
	sendSettingsInit := true

	conn0 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer0 := NewFuzzer(conn0, restartFuzzer)
	go fuzzer0.PingFuzzer()

	conn1 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer1 := NewFuzzer(conn1, restartFuzzer)
	go fuzzer1.RawFrameFuzzer()

	conn2 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer2 := NewFuzzer(conn2, restartFuzzer)
	go fuzzer2.PriorityFuzzer()
	go fuzzer2.PingFuzzer()
	go fuzzer2.HeaderFuzzer()

	conn3 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer3 := NewFuzzer(conn3, restartFuzzer)
	go fuzzer3.PriorityFuzzer()
	go fuzzer3.PingFuzzer()
	go fuzzer3.HeaderFuzzer()
	go fuzzer3.WindowUpdateFuzzer()

	conn4 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer4 := NewFuzzer(conn4, restartFuzzer)
	go fuzzer4.PriorityFuzzer()
	go fuzzer4.PingFuzzer()
	go fuzzer4.HeaderFuzzer()
	go fuzzer4.ResetFuzzer()

	conn5 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer5 := NewFuzzer(conn5, restartFuzzer)
	go fuzzer5.SettingsFuzzer()
	go fuzzer5.HeaderFuzzer()

	conn6 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer6 := NewFuzzer(conn6, restartFuzzer)
	go fuzzer6.DataFuzzer()
	go fuzzer6.HeaderFuzzer()

	conn7 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer7 := NewFuzzer(conn7, restartFuzzer)
	go fuzzer7.ContinuationFuzzer()
	go fuzzer7.HeaderFuzzer()

	conn8 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer8 := NewFuzzer(conn8, restartFuzzer)
	go fuzzer8.PushPromiseFuzzer()
	go fuzzer8.HeaderFuzzer()

	conn9 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer9 := NewFuzzer(conn9, restartFuzzer)
	go fuzzer9.RawTCPFuzzer()

	conn10 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer10 := NewFuzzer(conn10, restartFuzzer)
	go fuzzer10.RawTCPFuzzer()

	conn11 := NewConnection(target, tls, false, !sendSettingsInit)
	fuzzer11 := NewFuzzer(conn11, restartFuzzer)
	go fuzzer11.RawTCPFuzzer()

	conn12 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer12 := NewFuzzer(conn12, restartFuzzer)
	go fuzzer12.PriorityFuzzer()
	go fuzzer12.PingFuzzer()
	go fuzzer12.HeaderFuzzer()
	go fuzzer12.PushPromiseFuzzer()
	go fuzzer12.ContinuationFuzzer()
	go fuzzer12.WindowUpdateFuzzer()
}
