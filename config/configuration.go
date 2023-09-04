package config

import (
	"fmt"
	"reflect"
	"sync/atomic"

	"dario.cat/mergo"
	"github.com/creasty/defaults"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

// Any copy of this pointer is guaranteed to be consistent (immutable)
var ConfigurationPointer *atomic.Pointer[Configuration] = &atomic.Pointer[Configuration]{}

type Configuration struct {
	Policy struct {
		Directories      []string `default:"[\"./policies/\"]" json:"directories"`
		WatchDirectories bool     `default:"true" json:"watch_directories"`
		StrictMode       bool     `default:"true" json:"strict_mode"`
		PrintEnabled     bool     `default:"true" json:"print_enabled"`
	} `json:"policy"`
	Reflection struct {
		Enabled bool `default:"true" json:"enabled"`
	} `json:"reflection"`
	Authorizer struct {
		IncludesMetrics bool `default:"false" json:"includes_metrics"`
		Listener        struct {
			Type    string `default:"unix" json:"type"`
			Address string `default:"./serve.sock" json:"address"`
		} `json:"listener"`
	} `json:"authorizer"`
	Metrics struct {
		Enabled  bool   `default:"true" json:"enabled"`
		Path     string `default:"/metrics" json:"path"`
		Listener struct {
			Type    string `default:"tcp" json:"type"`
			Address string `default:":9100" json:"address"`
		} `json:"listener"`
	} `json:"metrics"`
	Reload struct {
		Configuration bool `default:"true" json:"configuration"`
		Policies      bool `default:"true" json:"policies"`
		ReopenLogFile bool `default:"true" json:"reopen_log_file"`
	} `json:"reload"`
	Log struct {
		Filename       string `default:"stderr" json:"filename"`
		Level          string `default:"info" json:"level"`
		Input          bool   `default:"true" json:"input"`
		DetailedResult bool   `default:"true" json:"detailed_result"`
	} `json:"log"`
}

// Thread safe: we atomically swap in the new ConfigurationPointer object; while
// we don't guarantee a winner, we do guarantee a valid ConfigurationPointer. We
// return the new Configuration that we Store()d in the ConfigurationPointer.
func LoadConfiguration() (*Configuration, error) {
	var newConfiguration *Configuration = &Configuration{}
	if err := defaults.Set(newConfiguration); err != nil {
		return nil, fmt.Errorf("unable to set default configuration (likely a bug): %w", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("unable to read configuration: %w", err)
	}
	contextualLogger := slog.With(slog.String("context", "loading configuration"))
	if viper.ConfigFileUsed() != "" {
		contextualLogger = contextualLogger.With(slog.String("config_file", viper.ConfigFileUsed()))
	}
	if err := mergo.Map(
		newConfiguration,
		viper.AllSettings(),
		mergo.WithOverride,
		mergo.WithTypeCheck,
		mergo.WithTransformers(
			stringListTransformer{
				logger: contextualLogger,
			},
		),
	); err != nil {
		return nil, fmt.Errorf("unable to merge configuration (likely a bug): %w", err)
	}
	ConfigurationPointer.Store(newConfiguration)
	return newConfiguration, nil
}

func InitializeConfiguration() {
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/docker-socket-authorizer/")
	viper.AddConfigPath(".")
}

type stringListTransformer struct {
	logger *slog.Logger
}

// Transforms a slice of interfaces into a slice of strings, discarding any non-string values and logging a warning.
func (t stringListTransformer) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	if typ == reflect.TypeOf([]string{}) {
		return func(dst, src reflect.Value) error {
			if dst.CanSet() && src.Kind() == reflect.Slice {
				listValues := reflect.MakeSlice(dst.Type(), 0, src.Cap())
				for i := 0; i < src.Len(); i++ {
					val := src.Index(i).Interface()
					switch val := val.(type) {
					case string:
						listValues = reflect.Append(listValues, reflect.ValueOf(val))
					default:
						t.logger.Warn("Unable to read value in list as a string (may need to be quoted)", slog.Any("value", val))
					}
				}
				dst.Set(listValues)
			}
			return nil
		}
	}
	return nil
}
