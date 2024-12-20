package rtio

import (
	"github.com/mkrainbow/rtio-device-sdk-go/pkg/logsettings"
)

// SetLogConfigs  sets the logging configuration (text, json) and log Level (debug, info, warn, error)
func SetLogConfigs(format, level string) {
	logsettings.Set(format, level)
}

func init() {
	SetLogConfigs("text", "warn")
}
