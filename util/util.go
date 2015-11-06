package util

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/bradfitz/http2"
)

func FromBase64(in string) []byte {
	data, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return data
}

func ToBase64(in []byte) string {
	data := []byte(in)
	return base64.StdEncoding.EncodeToString(data)
}

func WaitForEnter() {
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
}

func FromJSON(in []byte) map[string]interface{} {
	out := make(map[string]interface{})
	err := json.Unmarshal(in, &out)
	if err != nil {
		panic(err)
	}
	return out
}

func ToJSON(v interface{}) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return out
}

func HTTP2Dial(host string, isTLS bool) (net.Conn, error) {
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
		log.Printf("Negotiated protocol %q", state.NegotiatedProtocol)
		if !state.NegotiatedProtocolIsMutual || state.NegotiatedProtocol == "" {
			return nil, err
		}

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

func ReadLines(filename string) []string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(data), "\n")

	// Remove last line if empty
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[0 : len(lines)-1]
	}
	return lines
}

func ReadPreface(conn net.Conn) (error, bool) {
	buffer := make([]byte, len(http2.ClientPreface))
	n, err := conn.Read(buffer)
	if err != nil {
		return err, false
	}
	return nil, bytes.Compare([]byte(http2.ClientPreface), buffer[:n]) == 0
}

func SendPreface(conn net.Conn) error {
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return err
	}
	return nil
}
