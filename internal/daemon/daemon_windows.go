//go:build windows

// Package daemon provides daemon lifecycle management for miond on Windows.
package daemon

import (
	"context"
	"log"
	"os"
	"os/signal"
)

// Run executes fn in a daemon context, blocking until os.Interrupt (Ctrl+C)
// is received. The context passed to fn is cancelled on signal.
func Run(fn func(ctx context.Context) error) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("[daemon] pid=%d starting", os.Getpid())

	errCh := make(chan error, 1)
	go func() {
		errCh <- fn(ctx)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Printf("[daemon] exited with error: %v", err)
		}
		return err
	case <-ctx.Done():
		log.Printf("[daemon] received signal, shutting down...")
		return nil
	}
}
