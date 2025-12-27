package authz

import (
	"context"
	"fmt"
	"log/slog"
)

// SLogLogger wraps the standard library slog.Logger
type SLogLogger struct {
	l *slog.Logger
}

func NewSLogLogger(l *slog.Logger) *SLogLogger {
	if l == nil {
		l = slog.Default()
	}
	return &SLogLogger{l: l}
}

func (s *SLogLogger) Debug(msg string, keyvals ...any) {
	attrs := make([]slog.Attr, 0, len(keyvals)/2)
	for i := 0; i < len(keyvals)-1; i += 2 {
		k := keyvals[i]
		v := keyvals[i+1]
		attrs = append(attrs, toSlogAttr(k, v))
	}
	s.l.Log(context.TODO(), slog.LevelDebug, msg, keyvals...)
}

func (s *SLogLogger) Info(msg string, keyvals ...any) {
	attrs := make([]slog.Attr, 0, len(keyvals)/2)
	for i := 0; i < len(keyvals)-1; i += 2 {
		k := keyvals[i]
		v := keyvals[i+1]
		attrs = append(attrs, toSlogAttr(k, v))
	}
	s.l.Log(context.TODO(), slog.LevelInfo, msg, keyvals...)
}

func (s *SLogLogger) Error(msg string, keyvals ...any) {
	attrs := make([]slog.Attr, 0, len(keyvals)/2)
	for i := 0; i < len(keyvals)-1; i += 2 {
		k := keyvals[i]
		v := keyvals[i+1]
		attrs = append(attrs, toSlogAttr(k, v))
	}
	s.l.Log(context.TODO(), slog.LevelError, msg, keyvals...)
}

// toSlogAttr converts a key/value pair to slog.Attr
func toSlogAttr(k any, v any) slog.Attr {
	ks := ""
	switch s := k.(type) {
	case string:
		ks = s
	default:
		ks = fmt.Sprint(k)
	}
	// choose representation
	switch vv := v.(type) {
	case string:
		return slog.String(ks, vv)
	case bool:
		return slog.Bool(ks, vv)
	case int:
		return slog.Int(ks, vv)
	default:
		return slog.Any(ks, vv)
	}
}
