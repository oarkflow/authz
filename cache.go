package authz

type Cache interface {
	Get(key any) (any, bool)
	Set(key any, value any, cost int64) bool
	Wait()
	Clear()
	Close() error
}

type NoopCache struct{}

func (NoopCache) Get(key any) (any, bool) { return nil, false }

func (NoopCache) Set(key any, value any, cost int64) bool { return false }

func (NoopCache) Wait() {}

func (NoopCache) Clear() {}

func (NoopCache) Close() error { return nil }
