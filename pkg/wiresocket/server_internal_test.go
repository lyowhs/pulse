package wiresocket

// server_internal_test.go — unit tests for ServerConfig.defaults() and the
// diagnostic counter helpers.

import (
	"testing"
)

// TestWorkChannelSizeFormula verifies that defaults() computes WorkChannelSize
// as max(WorkerCount*64, EventBufSize*fragsPerEvent*2+64, 4096), which ensures
// the work channel can absorb an initial burst plus a concurrent retransmit
// burst of the same size without dropping packets.
//
// EventBufSize and MaxIncompleteFrames are set explicitly to bypass the
// ProbeUDPRecvBufSize kernel call and make the test deterministic.
func TestWorkChannelSizeFormula(t *testing.T) {
	t.Parallel()

	// maxFrag for MTU=1472: 1472 - sizeDataHeader(16) - sizeFragmentHeader(8) - sizeAEADTag(16) = 1432
	const mtu1472 = 1472
	const maxFrag1472 = mtu1472 - sizeDataHeader - sizeFragmentHeader - sizeAEADTag // 1432

	cases := []struct {
		name            string
		mtu             int
		maxPayload      int // MaxEventPayloadSize
		eventBufSize    int // set explicitly to bypass ProbeUDPRecvBufSize
		workerCount     int
		wantChannelSize int
	}{
		{
			// Typical loopback bench: 1472 MTU, 1024-byte payload fits in one
			// fragment; inflightCap=2137.  The *2 factor means the channel holds
			// the initial burst (2137) + one retransmit burst (2137) = 4338 > 4096.
			name:            "single-frag inflightCap=2137",
			mtu:             mtu1472,
			maxPayload:      1024,
			eventBufSize:    2137,
			workerCount:     2,
			wantChannelSize: 2*2137*1 + 64, // = 4338
		},
		{
			// Multi-fragment payload: 4096 bytes at MTU=1472 → fragsPerEvent=3
			// (ceil(4096/1432)=3).  WorkChannelSize must account for 3×the events.
			name:            "multi-frag fragsPerEvent=3",
			mtu:             mtu1472,
			maxPayload:      4096,
			eventBufSize:    100,
			workerCount:     2,
			wantChannelSize: 4096, // max(128, 100*3*2+64=664, 4096) = 4096
		},
		{
			// Very small EventBufSize: the 4096 floor must apply.
			name:            "small EventBufSize floor",
			mtu:             mtu1472,
			maxPayload:      128,
			eventBufSize:    10,
			workerCount:     2,
			wantChannelSize: 4096, // max(128, 10*1*2+64=84, 4096) = 4096
		},
		{
			// Large worker pool: WorkerCount*64 dominates when EventBufSize is small.
			name:            "large WorkerCount dominates",
			mtu:             mtu1472,
			maxPayload:      128,
			eventBufSize:    10,
			workerCount:     100,
			wantChannelSize: 100 * 64, // max(6400, 84, 4096) = 6400
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
				// Compute fragsPerEvent for the error message.
				maxFrag := tc.mtu - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
				fragsPerEvent := 1
				if tc.maxPayload > maxFrag {
					fragsPerEvent = (tc.maxPayload + maxFrag - 1) / maxFrag
				}
				t.Errorf("WorkChannelSize = %d, want %d (EventBufSize=%d fragsPerEvent=%d WorkerCount=%d)",
					cfg.WorkChannelSize, tc.wantChannelSize,
					tc.eventBufSize, fragsPerEvent, tc.workerCount)
			}
		})
	}
	_ = maxFrag1472 // used only in comments; keep the const visible
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
