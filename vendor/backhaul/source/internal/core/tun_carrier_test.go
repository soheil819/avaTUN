package core

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTUNMuxCarriersDuplexAndReconnect(t *testing.T) {
	for _, kind := range []string{"tcpmux", "xtcpmux", "wsmux", "wssmux", "xwsmux"} {
		t.Run(kind, func(t *testing.T) {
			a, fa := pumpEngine(t)
			b, fb := pumpEngine(t)
			a.cfg.Defaults()
			b.cfg.Defaults()
			a.cfg.TUN.MTU = 1500
			b.cfg.TUN.MTU = 1500
			a.cfg.Transport.Type = "tun"
			b.cfg.Transport.Type = "tun"
			a.cfg.TUN.Carrier = kind
			b.cfg.TUN.Carrier = kind
			a.cfg.Listener.BindAddr = "127.0.0.1:12345"
			b.cfg.Dialer.RemoteAddr = "127.0.0.1:12345"
			for generation := 0; generation < 2; generation++ {
				left, right := net.Pipe()
				done := make(chan bool, 2)
				go func() { a.tunCarrierDuplex(fa, left); done <- true }()
				go func() { b.tunCarrierDuplex(fb, right); done <- true }()
				time.Sleep(30 * time.Millisecond)
				for _, pair := range [][2]*fakeTUN{{fa, fb}, {fb, fa}} {
					packet := testPacket(100, uint16(generation+1))
					pair[0].input <- packet
					select {
					case got := <-pair[1].output:
						if !bytes.Equal(got, packet) {
							t.Fatal("changed IP packet")
						}
					case <-time.After(3 * time.Second):
						t.Fatal("no IP packet")
					}
				}
				left.Close()
				right.Close()
				for i := 0; i < 2; i++ {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Fatal("carrier cleanup blocked")
					}
				}
			}
		})
	}
}
