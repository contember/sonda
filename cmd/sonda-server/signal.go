package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// receivedSignal is the cancel cause of the context returned by cancelOnSignal.
type receivedSignal struct{ signal os.Signal }

func (r receivedSignal) Error() string { return "received " + signalName(r.signal) }

// cancelOnSignal returns a context canceled when one of signals arrives. It logs the signal
// as it arrives, before any shutdown work, so a stop shows in the log even during startup.
// Go does not expose siginfo, so the sender's pid is unknown; ppid names the supervisor.
func cancelOnSignal(parent context.Context, log *slog.Logger, signals ...os.Signal) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, signals...)
	go func() {
		select {
		case s := <-ch:
			log.Warn("received signal, shutting down", "signal", signalName(s), "pid", os.Getpid(), "ppid", os.Getppid())
			cancel(receivedSignal{s})
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		cancel(nil)
	}
}

func signalName(s os.Signal) string {
	if sig, ok := s.(unix.Signal); ok {
		if name := unix.SignalName(sig); name != "" {
			return name
		}
	}
	return s.String()
}
