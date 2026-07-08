package authz

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
)

// contextRequestIDKey is the key for request IDs in contexts.
type contextRequestIDKey struct{}

func contextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextRequestIDKey{}, id)
}

// RequestIDFromContext extracts the request ID from a context.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v := ctx.Value(contextRequestIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Wrapper functions to allow testing without build constraints.
var aesNewCipher = aes.NewCipher
var cipherNewGCM = cipher.NewGCM
