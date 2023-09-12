package lifecycle

import (
	"fmt"

	"github.com/mjec/docker-socket-authorizer/config"
	"github.com/mjec/docker-socket-authorizer/internal/o11y"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

// This does the very first stuff that needs to be done, before we can do anything else.
// Namely:
// - Load the configuration
// - Configure the logger
func Bootstrap() config.Configuration {
	config.InitializeConfiguration()
	// ConfigureLogger() guarantees we can use slog.Error() after it's run, but no earlier.
	// However, we can't call ConfigureLogger() until we have read the config. So we save any
	// error we get reading the config, go off and run ConfigureLogger(), then log both the
	// config loading error (if any) and the logger configuration error (if any).
	// Hence these two lines MUST remain together, in this order; even though it'd be nice to
	// use if err := ...; err != nil { ... } constructs.
	cfg, loadConfigurationErr := config.LoadConfiguration()
	if loadConfigurationErr != nil {
		cfg = config.DefaultConfiguration()
		if !config.ConfigurationPointer.CompareAndSwap(nil, cfg) {
			panic(fmt.Errorf("unable to set configuration to default (likely a bug) after failing to load configuration: %w", loadConfigurationErr))
		}
	}
	configureLoggerErr := o11y.ConfigureLogger()
	// Now we can record those errors, which we do in the order in which they ocurred.
	if loadConfigurationErr != nil {
		var contextualLogger *slog.Logger = slog.With(slog.Any("error", loadConfigurationErr))
		if viper.ConfigFileUsed() == "" {
			contextualLogger = contextualLogger.With(slog.String("file", viper.ConfigFileUsed()))
		}
		contextualLogger.Warn("Unable to load configuration file; continuing with defaults", slog.Any("error", loadConfigurationErr))
	}
	if configureLoggerErr != nil {
		slog.Error("Logger configuration failed, continuing with defaults", slog.Any("error", configureLoggerErr))
	}

	return *cfg
}
