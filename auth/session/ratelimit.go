package session

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// rateLimitMax is the maximum number of authentication attempts
	// per EGN within the rate limit window.
	rateLimitMax = 5

	// rateLimitWindow is the sliding window for rate limiting.
	rateLimitWindow = 10 * time.Minute

	ratePrefix = "egn_rate:"
)

// RateLimiter enforces per-EGN authentication rate limits using Redis.
// Each EGN is allowed at most 5 attempts per 10-minute window.
type RateLimiter struct {
	client *redis.Client
}

// NewRateLimiter returns a RateLimiter backed by the given Redis client.
func NewRateLimiter(client *redis.Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// Allow checks whether the given EGN is within its rate limit.
// It increments the counter and returns true if the request is allowed,
// or false if the EGN has exceeded the limit. The window TTL is set
// on the first request and resets after expiry.
func (rl *RateLimiter) Allow(ctx context.Context, egn string) (bool, error) {
	key := ratePrefix + egn
	pipe := rl.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, rateLimitWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("rate limit check: %w", err)
	}
	return incr.Val() <= rateLimitMax, nil
}
