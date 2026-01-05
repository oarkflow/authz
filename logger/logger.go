package logger

type Logger interface {
	Error(msg string, keyvals ...any)
	Info(msg string, keyvals ...any)
	Debug(msg string, keyvals ...any)
}

// TraceIDFunc generates a correlation/trace ID string for each request/log.
type TraceIDFunc func() string // It should be cheap and safe for concurrent calls.
