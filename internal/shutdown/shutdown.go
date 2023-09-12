package shutdown

import (
	"context"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

const TIMEOUT_SECONDS float64 = 1

type gracefulShutdownManager struct {
	shutdownOnce    *sync.Once
	shutdownContext *context.Context // only access through shutdownOnce!
	shutdownChannel chan struct{}
	onShutdown      map[string]func()
	onShutdownLock  *sync.Mutex
	waitOnce        *sync.Once
}

type waitGroupKeyT struct{}

var waitGroupKey waitGroupKeyT = waitGroupKeyT{}

var shutdownManager gracefulShutdownManager = gracefulShutdownManager{
	shutdownOnce:    &sync.Once{},
	shutdownContext: nil,
	shutdownChannel: make(chan struct{}, 1), // this is buffered in case we shut down before we start waiting for it
	onShutdown:      map[string]func(){},
	onShutdownLock:  &sync.Mutex{},
	waitOnce:        &sync.Once{},
}

// Receives functions to run as goroutines on shutdown. If f is nil, the function registered under key is removed.
// If the shutdown has already started, the function will be run immediately. As such, it is idiomatic to use
// `defer shutdown.OnShutdown("key", func() { ... })` to ensure the function isn't run too early.
func OnShutdown(key string, f func()) {
	if shutdownManager.shutdownContext != nil {
		waitGroup := (*shutdownManager.shutdownContext).Value(waitGroupKey).(*sync.WaitGroup)
		waitGroup.Add(1)
		go func(f func(), g *sync.WaitGroup) { f(); g.Add(-1) }(f, waitGroup)
		return
	}

	shutdownManager.onShutdownLock.Lock()
	defer shutdownManager.onShutdownLock.Unlock()

	if f != nil {
		shutdownManager.onShutdown[key] = f
	} else {
		delete(shutdownManager.onShutdown, key)
	}
}

// Returns true if and only if the shutdown was requested by this call. If false, we were already shutting down.
// Calls logFunc(reason) if and only if the shutdown was requested by this call.
func Shutdown(reason string, logLevel slog.Level, logger *slog.Logger) bool {
	var firstCall bool = false
	shutdownManager.shutdownOnce.Do(func() {
		waitGroup := sync.WaitGroup{}
		shuttingDownContext, cancelShutdown := context.WithTimeout(
			context.WithValue(context.Background(), waitGroupKey, &waitGroup),
			time.Duration(TIMEOUT_SECONDS*float64(time.Second)),
		)

		if logger == nil {
			logger = slog.Default()
		}
		logger.Log(shuttingDownContext, logLevel, "Shutting down", slog.String("reason", reason))

		// Once shutdownContext is set, OnShutdown() will start immediately running shutdown handlers
		shutdownManager.onShutdownLock.Lock()
		shutdownManager.shutdownContext = &shuttingDownContext
		shutdownManager.onShutdownLock.Unlock()

		for key, f := range shutdownManager.onShutdown {
			slog.Debug("Executing shutdown hook", slog.String("key", key))
			waitGroup.Add(1)
			go func(f func(), g *sync.WaitGroup) { f(); g.Add(-1) }(f, &waitGroup)
		}

		go func(cancelShutdown context.CancelFunc, g *sync.WaitGroup) {
			g.Wait()
			cancelShutdown()
		}(cancelShutdown, &waitGroup)

		go func(ctx context.Context) {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				slog.Warn("Shutdown hooks did not complete before timeout; exiting anyway", slog.Float64("timeout_seconds", TIMEOUT_SECONDS))
			}
			shutdownManager.shutdownChannel <- struct{}{}
			close(shutdownManager.shutdownChannel)
		}(shuttingDownContext)

		firstCall = true
	})
	return firstCall
}

// Blocks until shutdown is requested, but only on the first call. Subsequent calls have no effect and return immediately.
func WaitForShutdown() {
	shutdownManager.waitOnce.Do(func() {
		<-shutdownManager.shutdownChannel
	})
}
