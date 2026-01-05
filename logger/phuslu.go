package logger

import (
	"fmt"

	phlog "github.com/oarkflow/log"
)

// PhusluLogger wraps the phuslu-style phlog package
type PhusluLogger struct{}

func NewPhusluLogger() *PhusluLogger { return &PhusluLogger{} }

func (p *PhusluLogger) Debug(msg string, keyvals ...any) {
	b := phlog.Debug()
	for i := 0; i < len(keyvals)-1; i += 2 {
		k := keyvals[i]
		v := keyvals[i+1]
		ks := fmt.Sprint(k)
		switch vv := v.(type) {
		case string:
			b = b.Str(ks, vv)
		case bool:
			b = b.Bool(ks, vv)
		case int:
			b = b.Int(ks, vv)
		default:
			b = b.Any(ks, vv)
		}
	}
	b.Msg(msg)
}

func (p *PhusluLogger) Info(msg string, keyvals ...any) {
	b := phlog.Info()
	for i := 0; i < len(keyvals)-1; i += 2 {
		k := keyvals[i]
		v := keyvals[i+1]
		ks := fmt.Sprint(k)
		switch vv := v.(type) {
		case string:
			b = b.Str(ks, vv)
		case bool:
			b = b.Bool(ks, vv)
		case int:
			b = b.Int(ks, vv)
		default:
			b = b.Any(ks, vv)
		}
	}
	b.Msg(msg)
}

func (p *PhusluLogger) Error(msg string, keyvals ...any) {
	b := phlog.Error()
	for i := 0; i < len(keyvals)-1; i += 2 {
		k := keyvals[i]
		v := keyvals[i+1]
		ks := fmt.Sprint(k)
		switch vv := v.(type) {
		case string:
			b = b.Str(ks, vv)
		case bool:
			b = b.Bool(ks, vv)
		case int:
			b = b.Int(ks, vv)
		default:
			b = b.Any(ks, vv)
		}
	}
	b.Msg(msg)
}
