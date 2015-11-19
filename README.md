# http2fuzz (No longer under development)

HTTP2 fuzzer built in Golang.

![Fuzzer](/docs/http2fuzz.gif)

## Usage

    $ make build
    $ ./http2fuzz --help
    Usage of ./http2fuzz:
         -fuzz-delay=100: number of milliseconds to wait between each request per strategy
         -listen="0.0.0.0": interface to listen from
         -port="8000": port to listen from
         -restart-delay=10: number a milliseconds to wait between broken connections
         -target="": HTTP2 server to fuzz in host:port format
    $ ./http2fuzz --target "localhost:443"

## Description

http2fuzz is a semi-intelligent fuzzer. It knows how to build valid http2 frames of each type (Pings/Data/Settings etc).

While it's subject to change, the core idea will be the same. The code instantiates 'fuzzer' objects. These fuzzer objects each control one TLS connection, and each fuzzer kicks off a couple of fuzzing strategies.

For example, one of the fuzzer kicks off three different strategies: PriorityFuzzer, PingFuzzer, and HeaderFuzzer. So on the single TLS connection, we are sending a bunch of Priority/Ping/Header frames with garbage values. If at anytime the TLS connection goes does, the connection is restablished.

### Strategies

SettingsFuzzer:
- Picks a random number between 0-5
- Appends that many random settings with random values to a SettingsFrame

HeaderFuzzer:
- Picks a random number between 0-5
- Appends that many random HTTP headers with random values to a HeadersFrame

PriorityFuzzer:
- Sends Priority frames with a random streamDependency, steamId, weight, and exclusive value

PingFuzzer:
- Sends a ping frame with a random 8 byte payload

ResetFuzzer:
- Sends a RST Frame with a random streamId and errorCode

WindowUpdateFuzzer:
- Sends a Window Update Frame with a random streamId, and incr value.

RawFrameFuzzer:
- Generates a random frameType (0-12), randomFlags (0-256), and streamId(2**31), and a random byte array of length 0-10000.
- Sends the invalid frame

DataFuzzer:
- Sends a Data Frame with a random streamId, endStream bool, and random payload between 0-10000 bytes

PushPromiseFuzzer:
- Sends a PushPromise Frame with a random payload of 0-10000 bytes, streamId, promiseId, endHeaders bool, and padlengnth (0-256)

ContinuationFuzzer:
- Sends a Continuation Frame with a random streamId, endStream bool and payload of length 0-10000 bytes.

RawTCPFuzzer:
- Establishes a TLS connection, and sends complete garbage to it. The payload is a byte array of length 0-10000.

### Fuzzers

Each fuzzer is built from strategies. Currently the fuzzers are:

Fuzzer 1:
- RawFrameFuzzer

Fuzzer 2:
- PriorityFuzzer
- PingFuzzer
- HeaderFuzzer

Fuzzer 3:
- PriorityFuzzer
- PingFuzzer
- HeaderFuzzer
- WindowUpdateFuzzer

Fuzzer 4:
- PriorityFuzzer
- PingFuzzer
- HeaderFuzzer
- ResetFuzzer

Fuzzer 5:
- SettingsFuzzer
- HeaderFuzzer

Fuzzer 6:
- DataFuzzer
- HeaderFuzzer

Fuzzer 7:
- ContinuationFuzzer
- HeaderFuzzer

Fuzzer 8:
- PushPromiseFuzzer
- HeaderFuzzer

Fuzzer 9:
- RawTCPFuzzer

Fuzzer 10:
- RawTCPFuzzer (without clientpreface)

## Code Layout

```
http2fuzz/
    certs/     Holds localhost certifcates for fuzzing as an http2 server
    docs/      Holds documents and pictures
    fuzzer/    Holds the actual fuzzing code for client/server, along with an http2 connection wrapper class
    replay/    Holds code for replaying packets from a json file
    util/      Holds common utility functions
```

fuzzer/connection.go conatins the Connection struct. This structure sits on top of the actual TLS/TCP connection. It defines a number of methods for sending HTTP2 frames on this connection. Also handles the HPACK encoding/decoding.

fuzzer/fuzzer.go contains all the fuzzing strategies.

## Contact

stuartlarsen@yahoo-inc.com

## Copyright

Copyright 2015 Yahoo Inc. Licensed under the BSD license, see LICENSE file for terms. Written by Stuart Larsen
