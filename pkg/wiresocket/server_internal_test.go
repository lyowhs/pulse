package wiresocket

// server_internal_test.go — unit tests for ServerConfig.defaults() and the
// diagnostic counter helpers.

import (
	"testing"
)

// TestWorkChannelSizeFormula verifies that defaults() computes WorkChannelSize
// as max(WorkerCount*64, frameCount*fragsPerEvent*4+256, 4096), where frameCount
// = EventBufSize (worst-case: 1 event per frame).  Using EventBufSize directly
// (not EventBufSize/eventsPerPacket) ensures the work channel is large enough
// even when the coalescer timer fires early and frames carry few events.
//
// EventBufSize and MaxIncompleteFrames are set explicitly to bypass the
// ProbeUDPRecvBufSize kernel call and make the test deterministic.
func TestWorkChannelSizeFormula(t *testing.T) {
	t.Parallel()

	// maxFrag for MTU=1472: 1472 - sizeDataHeader(12) - sizeFragmentHeader(8) - sizeAEADTag(16) = 1436
	const mtu1472 = 1472
	const maxFrag1472 = mtu1472 - sizeDataHeader - sizeFragmentHeader - sizeAEADTag // 1436

	cases := []struct {
		name            string
		mtu             int
		maxPayload      int // MaxEventPayloadSize
		eventBufSize    int // set explicitly to bypass ProbeUDPRecvBufSize
		workerCount     int
		wantChannelSize int
	}{
		{
			// Typical loopback bench: 1472 MTU, 1024-byte payload.
			// evtWire=1028, ep=(1436-32)/1028=1 → eventsPerPacket=1.
			// frameCount=EventBufSize=2137 → max(128, 2137*1*4+256=8804, 4096) = 8804.
			name:            "single-frag inflightCap=2137",
			mtu:             mtu1472,
			maxPayload:      1024,
			eventBufSize:    2137,
			workerCount:     2,
			wantChannelSize: 4*2137*1 + 256, // = 8804
		},
		{
			// Multi-fragment payload: 4096 bytes at MTU=1472 → fragsPerEvent=3
			// (ceil(4096/1436)=3).  WorkChannelSize must account for 3× the frames.
			// eventsPerPacket=1 (fragsPerEvent>1 → skip).  frameCount=EventBufSize=100.
			// max(128, 100*3*4+256=1456, 4096) = 4096.
			name:            "multi-frag fragsPerEvent=3",
			mtu:             mtu1472,
			maxPayload:      4096,
			eventBufSize:    100,
			workerCount:     2,
			wantChannelSize: 4096, // max(128, 100*3*4+256=1456, 4096) = 4096
		},
		{
			// Very small EventBufSize: the 4096 floor must apply.
			// payload=128: evtWire=132, ep=(1436-32)/132=10 → eventsPerPacket=10.
			// frameCount=EventBufSize=10 → max(128, 10*1*4+256=296, 4096) = 4096.
			name:            "small EventBufSize floor",
			mtu:             mtu1472,
			maxPayload:      128,
			eventBufSize:    10,
			workerCount:     2,
			wantChannelSize: 4096, // max(128, 1*1*4+256=260, 4096) = 4096
		},
		{
			// Large worker pool: WorkerCount*64 dominates when EventBufSize is small.
			// frameCount=EventBufSize=10 → max(6400, 296, 4096) = 6400.
			name:            "large WorkerCount dominates",
			mtu:             mtu1472,
			maxPayload:      128,
			eventBufSize:    10,
			workerCount:     100,
			wantChannelSize: 100 * 64, // max(6400, 260, 4096) = 6400
		},
		{
			// Explicit WorkChannelSize must not be overwritten.
			name:            "explicit WorkChannelSize preserved",
			mtu:             mtu1472,
			maxPayload:      1024,
			eventBufSize:    2137,
			workerCount:     2,
			wantChannelSize: 9999, // caller-set value
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := ServerConfig{
				MaxPacketSize:       tc.mtu,
				MaxEventPayloadSize: tc.maxPayload,
				EventBufSize:        tc.eventBufSize,
				MaxIncompleteFrames: tc.eventBufSize, // avoid second probe branch
				WorkerCount:         tc.workerCount,
			}
			if tc.name == "explicit WorkChannelSize preserved" {
				cfg.WorkChannelSize = tc.wantChannelSize
			}

			cfg.defaults()

			if cfg.WorkChannelSize != tc.wantChannelSize {
				// Compute fragsPerEvent and eventsPerPacket for the error message.
				maxFrag := tc.mtu - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
				fragsPerEvent := 1
				if tc.maxPayload > maxFrag {
					fragsPerEvent = (tc.maxPayload + maxFrag - 1) / maxFrag
				}
				eventsPerPacket := 1
				if fragsPerEvent == 1 && tc.maxPayload > 0 && maxFrag > frameHeaderBudget {
					evtWire := tc.maxPayload + 3
					if tc.maxPayload+1 >= 128 {
						evtWire++
					}
					if ep := (maxFrag - frameHeaderBudget) / evtWire; ep > 1 {
						eventsPerPacket = ep
					}
				}
				t.Errorf("WorkChannelSize = %d, want %d (EventBufSize=%d fragsPerEvent=%d eventsPerPacket=%d WorkerCount=%d)",
					cfg.WorkChannelSize, tc.wantChannelSize,
					tc.eventBufSize, fragsPerEvent, eventsPerPacket, tc.workerCount)
			}
		})
	}
	_ = maxFrag1472 // used only in comments above; keep the const visible
}

// TestResetDebugCounters verifies that ResetDebugCounters zeroes all four
// diagnostic atomics regardless of their prior values.
func TestResetDebugCounters(t *testing.T) {
	t.Parallel()

	DebugFlushLoopErrors.Store(42)
	DebugDataDroppedClosed.Store(7)
	DebugDataDroppedUnknown.Store(100)
	DebugWorkerQueueFull.Store(3)

	ResetDebugCounters()

	for _, tc := range []struct {
		name string
		got  int64
	}{
		{"DebugFlushLoopErrors", DebugFlushLoopErrors.Load()},
		{"DebugDataDroppedClosed", DebugDataDroppedClosed.Load()},
		{"DebugDataDroppedUnknown", DebugDataDroppedUnknown.Load()},
		{"DebugWorkerQueueFull", DebugWorkerQueueFull.Load()},
	} {
		if tc.got != 0 {
			t.Errorf("%s = %d after ResetDebugCounters, want 0", tc.name, tc.got)
		}
	}
}
