package logger

// NullLogger implements Logger but does nothing (useful for tests)
type NullLogger struct{}

func NewNullLogger() *NullLogger { return &NullLogger{} }

func (n *NullLogger) Debug(msg string, keyvals ...any) {}
func (n *NullLogger) Info(msg string, keyvals ...any)  {}
func (n *NullLogger) Error(msg string, keyvals ...any) {}
