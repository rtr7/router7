// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/crypto/ssh"
)

func handleChannel(newChannel ssh.NewChannel, prb *packetRingBuffer) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %q", t))
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func(channel ssh.Channel, requests <-chan *ssh.Request) {
		s := session{channel: channel}
		for req := range requests {
			if err := s.request(req, prb); err != nil {
				errmsg := []byte(err.Error())
				// Append a trailing newline; the error message is
				// displayed as-is by ssh(1).
				if errmsg[len(errmsg)-1] != '\n' {
					errmsg = append(errmsg, '\n')
				}
				req.Reply(false, errmsg)
				channel.Write(errmsg)
				channel.Close()
			}
		}
	}(channel, requests)
}

type session struct {
	channel ssh.Channel
}

func (s *session) request(req *ssh.Request, prb *packetRingBuffer) (err error) {
	switch req.Type {
	case "exec":
		if got, want := len(req.Payload), 4; got < want {
			return fmt.Errorf("exec request payload too short: got %d, want >= %d", got, want)
		}
		log.Printf("exec, wantReply %v, payload %q", req.WantReply, string(req.Payload[4:]))
		defer func() {
			if err != nil {
				log.Printf("exec done: %v", err)
			}
		}()

		ctx, canc := context.WithCancel(context.Background())
		defer canc()

		pcapw := pcapgo.NewWriter(s.channel)
		if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
			return fmt.Errorf("pcapw.WriteFileHeader: %v", err)
		}

		prb.Lock()
		packets, err := capturePackets(ctx)
		buffered := prb.packetsLocked()
		prb.Unlock()
		if err != nil {
			return fmt.Errorf("capturePackets: %v", err)
		}

		req.Reply(true, nil)

		for _, packet := range buffered {
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("pcap.WritePacket(): %v", err)
			}
		}

		for packet := range packets {
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("pcap.WritePacket(): %v", err)
			}
		}

		return nil

	default:
		return fmt.Errorf("unknown request type: %q", req.Type)
	}

	return nil
}

func loadHostKey(path string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(b)
}

type server struct {
	config *ssh.ServerConfig
	prb    *packetRingBuffer
}

func newServer(prb *packetRingBuffer) (*server, error) {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil // authorize all users
		},
	}

	signer, err := loadHostKey(*hostKeyPath)
	if err != nil {
		return nil, err
	}
	config.AddHostKey(signer)

	return &server{
		config: config,
		prb:    prb,
	}, nil
}

func (s *server) listenerFor(host string) *serverListener {
	return &serverListener{srv: s, host: host}
}

type serverListener struct {
	srv  *server
	host string
	ln   net.Listener
}

func (sl *serverListener) ListenAndServe() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(sl.host, "5022"))
	if err != nil {
		return err
	}
	sl.ln = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			_, chans, reqs, err := ssh.NewServerConn(conn, sl.srv.config)
			if err != nil {
				log.Printf("handshake: %v", err)
				return
			}

			// discard all out of band requests
			go ssh.DiscardRequests(reqs)

			for newChannel := range chans {
				handleChannel(newChannel, sl.srv.prb)
			}
		}(conn)
	}
	return nil
}

func (sl *serverListener) Close() error {
	return sl.ln.Close()
}
