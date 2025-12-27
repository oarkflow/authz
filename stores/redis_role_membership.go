package stores

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// RedisRoleMembershipStore stores subject->roles in Redis sets (key: rolemem:{subjectID})
type RedisRoleMembershipStore struct {
	client *redis.Client
	keyFmt string // format string, e.g. "rolemem:%s"
}

func NewRedisRoleMembershipStore(client *redis.Client) *RedisRoleMembershipStore {
	return &RedisRoleMembershipStore{client: client, keyFmt: "rolemem:%s"}
}

func (r *RedisRoleMembershipStore) key(subjectID string) string {
	return fmt.Sprintf(r.keyFmt, subjectID)
}

func (r *RedisRoleMembershipStore) AssignRole(ctx context.Context, subjectID, roleID string) error {
	return r.client.SAdd(ctx, r.key(subjectID), roleID).Err()
}

func (r *RedisRoleMembershipStore) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	return r.client.SRem(ctx, r.key(subjectID), roleID).Err()
}

func (r *RedisRoleMembershipStore) ListRoles(ctx context.Context, subjectID string) ([]string, error) {
	res, err := r.client.SMembers(ctx, r.key(subjectID)).Result()
	if err != nil {
		return nil, err
	}
	return res, nil
}
