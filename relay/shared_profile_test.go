package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSharedProfileCapacityDoesNotEvictExistingSessions(t *testing.T) {
	for _, sharedIP := range []bool{true, false} {
		t.Run(fmt.Sprint("sharedIP=", sharedIP), func(t *testing.T) {
			c := testConfig("127.0.0.1:1")
			c.Profiles[0].CarrierMode = "https"
			// Isolate capacity reuse from the separate connection-creation rate limiter.
			c.Limits.NewSessionsBurst = c.Limits.MaxSessionsGlobal + 2
			m := NewManager(c, [32]byte{1})
			defer m.Shutdown()
			var clients []CreateResult
			create := func(i int) (CreateResult, error) {
				ip := "198.51.100.1"
				if !sharedIP {
					ip = fmt.Sprintf("198.51.100.%d", i%200+1)
				}
				token, err := m.IssueBootstrap(&c.Profiles[0], ip)
				if err != nil {
					return CreateResult{}, err
				}
				return m.Create(token, ip, frame.Encode(frame.Hello, 0, []byte{1}))
			}
			if c.Limits.MaxSessionsGlobal != 128 {
				t.Fatalf("Review changed default session capacity: %d", c.Limits.MaxSessionsGlobal)
			}
			for i := 0; i < c.Limits.MaxSessionsGlobal; i++ {
				v, err := create(i)
				if err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
				clients = append(clients, v)
			}
			if _, err := create(128); !errors.Is(err, ErrLimit) {
				t.Fatalf("Expected capacity error, got %v", err)
			}
			for i, v := range clients {
				if _, err := m.Get(v.Token); err != nil {
					t.Fatalf("capacity refusal evicted client %d: %v", i, err)
				}
			}
			clients[0].Session.Close()
			waitFor(t, func() bool { return m.Capacity().Sessions == 127 })
			if _, err := create(129); err != nil {
				t.Fatalf("Closed client did not release capacity: %v", err)
			}
			for i, v := range clients[1:] {
				if _, err := m.Get(v.Token); err != nil {
					t.Fatalf("replacement evicted client %d: %v", i+1, err)
				}
			}
		})
	}
}

func TestSharedProfileConcurrentClientsKeepIndependentTraffic(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	c := testConfig(listener.Addr().String())
	c.Profiles[0].CarrierMode = "https"
	c.Timeouts.BackendDial = config.Duration(5 * time.Second)
	m := NewManager(c, [32]byte{1})
	defer m.Shutdown()
	clients := make([]CreateResult, 32)
	cursors := make([]uint64, len(clients))
	seen := map[string]bool{}
	for i := range clients {
		ip := fmt.Sprintf("198.51.100.%d", i%4+1)
		bootstrap, err := m.IssueBootstrap(&c.Profiles[0], ip)
		if err != nil {
			t.Fatal(err)
		}
		clients[i], err = m.Create(bootstrap, ip, frame.Encode(frame.Hello, 0, []byte{1}))
		if err != nil {
			t.Fatal(err)
		}
		if seen[clients[i].Token] {
			t.Fatal("different clients received the same session token")
		}
		seen[clients[i].Token] = true
	}
	round := func(sequence uint64, start int) {
		var wg sync.WaitGroup
		for i := start; i < len(clients); i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				payload := []byte(fmt.Sprintf("independent client %d round %d", i, sequence))
				batch := frame.Encode(frame.Data, 1, payload)
				if sequence == 1 {
					batch = append(frame.Encode(frame.Open, 1, nil), batch...)
				}
				if _, err := clients[i].Session.ProcessUp(sequence, batch); err != nil {
					t.Errorf("client %d uplink: %v", i, err)
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var received []byte
				for len(received) < len(payload) {
					body, cursor, err := clients[i].Session.Poll(ctx, cursors[i])
					if err != nil {
						t.Errorf("client %d downlink: %v", i, err)
						return
					}
					cursors[i] = cursor
					frames, err := frame.ParseAll(body, frame.MaxPayload)
					if err != nil {
						t.Error(err)
						return
					}
					for _, f := range frames {
						if f.Type == frame.Data {
							received = append(received, f.Payload...)
						}
					}
					if ctx.Err() != nil {
						t.Errorf("client %d timed out", i)
						return
					}
				}
				if !bytes.Equal(received, payload) {
					t.Errorf("client %d received another client's data", i)
				}
			}(i)
		}
		wg.Wait()
	}
	round(1, 0)
	clients[0].Session.Close()
	round(2, 1)
}
