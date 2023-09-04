package o11y

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/mjec/docker-socket-authorizer/config"
	"golang.org/x/exp/slog"
)

var logSettings = struct {
	mutex      *sync.Mutex
	logger     *slog.Logger
	configured bool
	fileCloser io.Closer
}{
	mutex:      &sync.Mutex{},
	logger:     nil,
	configured: false,
	fileCloser: nil,
}

// Thread safe; protected by a mutex.
func ConfigureLogger() error {
	logSettings.mutex.Lock()
	defer logSettings.mutex.Unlock()
	cfg := config.ConfigurationPointer

	var err error = nil
	var newFileCloser io.Closer = nil
	lvl := slog.LevelInfo
	output := os.Stderr

	if cfg == nil {
		err = combineErrors(err, fmt.Errorf("configuration object not set (likely an error loading config file on startup); proceeding with defaults"))
	} else {
		err = combineErrors(err, lvl.UnmarshalText([]byte(cfg.Log.Level)))
		if cfg.Log.Filename == "stderr" {
			output = os.Stderr
		} else if cfg.Log.Filename == "stdout" {
			output = os.Stdout
		} else {
			f, openFileErr := os.OpenFile(cfg.Log.Filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			err = combineErrors(err, openFileErr)
			if openFileErr == nil {
				output = f
				newFileCloser = f
			}
		}
	}

	logSettings.logger = slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: lvl}))
	if err == nil || !logSettings.configured {
		slog.SetDefault(logSettings.logger)
		if logSettings.fileCloser != nil {
			logSettings.fileCloser.Close()
		}
		logSettings.configured = true
		logSettings.fileCloser = newFileCloser
	}

	return err
}

func combineErrors(errors ...error) error {
	var output error
	for _, err := range errors {
		if err != nil {
			if output == nil {
				output = err
			} else {
				output = fmt.Errorf("%w\n%w", output, err)
			}
		}
	}
	return output
}
