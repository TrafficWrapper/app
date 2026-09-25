package transport

import (
	"errors"
	"log"
	"runtime/debug"
	"sync/atomic"
)

// debugDestinationLogs enables per-connection logs that name destination
// hosts and addresses. It is off in every build; a developer build can turn
// it on with
//
//	-ldflags "-X github.com/TrafficWrapper/app/core/transport.debugDestinationLogs=1"
//
// Release logs only carry counters and error kinds, never destinations.
var debugDestinationLogs = ""

func debugLogf(format string, args ...any) {
	if debugDestinationLogs != "" {
		log.Printf(format, args...)
	}
}

// recoveredPanics counts panics caught by recoverGoroutine.
var recoveredPanics atomic.Uint64

var errRecoveredPanic = errors.New("recovered panic")

// recoverGoroutine must be deferred directly at the top of a per-flow
// goroutine. A panic in one flow is logged and counted instead of killing
// the whole VPN process.
func recoverGoroutine(where string) {
	if r := recover(); r != nil {
		recoveredPanics.Add(1)
		log.Printf("transport: recovered panic in %s: %v\n%s", where, r, debug.Stack())
	}
}
