package server

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestTrackerKeepsTunnelWhileRDPOpen(t *testing.T) {
	var fired atomic.Bool
	tr := newTracker(50*time.Millisecond, func() { fired.Store(true) })
	defer tr.stop()

	tr.opened() // RDP connects before the grace runs out
	time.Sleep(150 * time.Millisecond)
	if fired.Load() {
		t.Fatal("tunnel closed while RDP was connected")
	}
	tr.opened() // a second connection (e.g. reconnect) overlapping the first
	tr.closed()
	time.Sleep(150 * time.Millisecond)
	if fired.Load() {
		t.Fatal("tunnel closed while one RDP connection was still open")
	}
	tr.closed() // last RDP connection ends: grace timer starts
	time.Sleep(150 * time.Millisecond)
	if !fired.Load() {
		t.Fatal("tunnel not closed after grace period")
	}
}

func TestTrackerReconnectWithinGrace(t *testing.T) {
	var fired atomic.Bool
	tr := newTracker(100*time.Millisecond, func() { fired.Store(true) })
	defer tr.stop()
	tr.opened()
	tr.closed()
	time.Sleep(40 * time.Millisecond)
	tr.opened() // reconnect inside the grace window cancels the timer
	time.Sleep(200 * time.Millisecond)
	if fired.Load() {
		t.Fatal("reconnect within grace did not keep tunnel open")
	}
}

func TestTrackerZeroNeverCloses(t *testing.T) {
	var fired atomic.Bool
	tr := newTracker(0, func() { fired.Store(true) })
	tr.opened()
	tr.closed()
	time.Sleep(50 * time.Millisecond)
	if fired.Load() {
		t.Fatal("grace 0 should never close")
	}
}
