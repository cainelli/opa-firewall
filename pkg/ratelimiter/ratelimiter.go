package ratelimiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter ...
type RateLimiter struct {
	buckets   map[string]*rate.Limiter
	mutex     *sync.RWMutex
	rateLimit rate.Limit
	burst     int
}

// NewRateLimiter .
func NewRateLimiter(rateLimit rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		buckets:   make(map[string]*rate.Limiter),
		mutex:     &sync.RWMutex{},
		rateLimit: rateLimit,
		burst:     burst,
	}
}

// GetBucket returns the rate limiter for the provided bucket if it exists.
// Otherwise calls AddBucket to add IP address to the map
func (rateLimiter *RateLimiter) GetBucket(bucketName string) *rate.Limiter {
	rateLimiter.mutex.Lock()
	limiter, exists := rateLimiter.buckets[bucketName]

	if !exists {
		rateLimiter.mutex.Unlock()
		return rateLimiter.addBucket(bucketName)
	}

	rateLimiter.mutex.Unlock()
	return limiter
}

// addBucket creates a new rate limiter and adds it to the buckets map,
// using the bucket name as the key
func (rateLimiter *RateLimiter) addBucket(bucketName string) *rate.Limiter {
	rateLimiter.mutex.Lock()
	defer rateLimiter.mutex.Unlock()

	limiter := rate.NewLimiter(rateLimiter.rateLimit, rateLimiter.burst)

	rateLimiter.buckets[bucketName] = limiter

	return limiter
}

// IsAllowed returns if a bucket has enough seats, it takes into account the event time it occours
func (rateLimiter *RateLimiter) IsAllowed(bucketName string, eventTime time.Time) (bool, error) {
	bucket := rateLimiter.GetBucket(bucketName)

	if !bucket.AllowN(eventTime, 1) {
		return false, nil
	}

	return true, nil
}
