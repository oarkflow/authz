package logger

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
	s.log(slog.LevelDebug, msg, keyvals...)
}

func (s *SLogLogger) Info(msg string, keyvals ...any) {
	s.log(slog.LevelInfo, msg, keyvals...)
}

func (s *SLogLogger) Error(msg string, keyvals ...any) {
	s.log(slog.LevelError, msg, keyvals...)
}

func (s *SLogLogger) log(level slog.Level, msg string, keyvals ...any) {
	attrs := make([]slog.Attr, 0, len(keyvals)/2)
	for i := 0; i < len(keyvals)-1; i += 2 {
		attrs = append(attrs, toSlogAttr(keyvals[i], keyvals[i+1]))
	}
	s.l.LogAttrs(context.Background(), level, msg, attrs...)
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
