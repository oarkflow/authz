package ristretto

import (
	"github.com/dgraph-io/ristretto"
	"github.com/oarkflow/authz"
)

type ristrettoCache struct {
	inner *ristretto.Cache
}

func New(numCounters, maxCost, bufferItems int64) (authz.Cache, error) {
	inner, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: int64(bufferItems),
	})
	if err != nil {
		return nil, err
	}
	return &ristrettoCache{inner: inner}, nil
}

func (c *ristrettoCache) Get(key any) (any, bool) { return c.inner.Get(key) }

func (c *ristrettoCache) Set(key any, value any, cost int64) bool { return c.inner.Set(key, value, cost) }

func (c *ristrettoCache) Wait() { c.inner.Wait() }

func (c *ristrettoCache) Clear() { c.inner.Clear() }

func (c *ristrettoCache) Close() error { c.inner.Close(); return nil }
