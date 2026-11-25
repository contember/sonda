package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestCancelOnSignalLogsTheSignal(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx, stop := cancelOnSignal(context.Background(), log, syscall.SIGUSR1)
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context not canceled after the signal")
	}

	var cause receivedSignal
	if !errors.As(context.Cause(ctx), &cause) || cause.signal != syscall.SIGUSR1 {
		t.Fatalf("cause = %v, want the received SIGUSR1", context.Cause(ctx))
	}
	var line struct {
		Level  string `json:"level"`
		Msg    string `json:"msg"`
		Signal string `json:"signal"`
		PID    int    `json:"pid"`
		PPID   int    `json:"ppid"`
	}
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line %q: %v", buf.String(), err)
	}
	if line.Level != "WARN" || line.Signal != "SIGUSR1" || line.PID != os.Getpid() || line.PPID != os.Getppid() {
		t.Fatalf("log line = %+v", line)
	}
}

func TestCancelOnSignalStopLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	ctx, stop := cancelOnSignal(context.Background(), slog.New(slog.NewJSONHandler(&buf, nil)), syscall.SIGUSR1)
	stop()
	<-ctx.Done()
	if context.Cause(ctx) != context.Canceled {
		t.Fatalf("cause = %v, want context.Canceled", context.Cause(ctx))
	}
	if buf.Len() != 0 {
		t.Fatalf("stop logged %q", buf.String())
	}
}
