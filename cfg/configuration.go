package cfg

import (
	"fmt"
	"reflect"

	"dario.cat/mergo"
	"github.com/creasty/defaults"
	"github.com/spf13/viper"
)

var Configuration *config

type config struct {
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
	} `json:"reload"`
	Log struct {
		Level          string `default:"info" json:"level"`
		Input          bool   `default:"true" json:"input"`
		DetailedResult bool   `default:"true" json:"detailed_result"`
	} `json:"log"`
}

func LoadConfiguration() error {
	Configuration = &config{}
	if err := defaults.Set(Configuration); err != nil {
		panic(err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}
	return mergo.MapWithOverwrite(Configuration, viper.AllSettings(), mergo.WithTransformers(stringListTransformer{}))
}

func InitializeConfiguration() {
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/docker-socket-authorizer/")
	viper.AddConfigPath(".")
}

type stringListTransformer struct {
}

func (t stringListTransformer) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	if typ == reflect.TypeOf([]string{}) {
		return func(dst, src reflect.Value) error {
			if dst.CanSet() && src.Kind() == reflect.Slice {
				dst.Set(reflect.MakeSlice(dst.Type(), src.Len(), src.Cap()))
				for i := 0; i < src.Len(); i++ {
					dst.Index(i).SetString(src.Index(i).Interface().(string))
				}
			}
			return nil
		}
	}
	return nil
}
