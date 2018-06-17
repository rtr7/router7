package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/gokrazy/gokrazy"
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

func (s *session) request(req *ssh.Request, prb *packetRingBuffer) error {
	switch req.Type {
	case "exec":
		if got, want := len(req.Payload), 4; got < want {
			return fmt.Errorf("exec request payload too short: got %d, want >= %d", got, want)
		}
		log.Printf("exec, wantReply %v, payload %q", req.WantReply, string(req.Payload[4:]))

		ctx, canc := context.WithCancel(context.Background())
		defer canc()

		pcapw := pcapgo.NewWriter(s.channel)
		if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
			return err
		}

		prb.Lock()
		packets, err := capturePackets(ctx)
		buffered := prb.packetsLocked()
		prb.Unlock()
		if err != nil {
			return err
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

func listenAndServe(prb *packetRingBuffer) error {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil // authorize all users
		},
	}

	signer, err := loadHostKey(*hostKeyPath)
	if err != nil {
		return err
	}
	config.AddHostKey(signer)

	accept := func(listener net.Listener) {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}

			go func(conn net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					log.Printf("handshake: %v", err)
					return
				}

				// discard all out of band requests
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					handleChannel(newChannel, prb)
				}
			}(conn)
		}
	}

	addrs, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		hostport := net.JoinHostPort(addr, "5022")
		listener, err := net.Listen("tcp", hostport)
		if err != nil {
			return err
		}
		fmt.Printf("listening on %s\n", hostport)
		go accept(listener)
	}

	fmt.Printf("host key fingerprint: %s\n", ssh.FingerprintSHA256(signer.PublicKey()))

	select {}

	return nil
}
