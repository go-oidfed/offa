package cache

import (
	"bytes"
	"fmt"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"

	fedcache "github.com/go-oidfed/lib/cache"

	"github.com/go-oidfed/offa/internal/config"
	"github.com/go-oidfed/offa/internal/model"
)

func Init() {
	if config.Get().SessionStorage.RedisAddr != "" {
		if err := fedcache.UseRedisCache(
			&redis.Options{
				Addr:     config.Get().SessionStorage.RedisAddr,
				Username: config.Get().SessionStorage.RedisUsername,
				Password: config.Get().SessionStorage.RedisPassword,
				DB:       config.Get().SessionStorage.RedisDB,
			},
		); err != nil {
			log.WithError(err).Fatal("could not init redis cache")
		}
	}
	if config.Get().SessionStorage.MemCachedAddr != "" {
		memcached = memcache.New(config.Get().SessionStorage.MemCachedAddr)
		if err := memcached.Ping(); err != nil {
			log.WithError(err).Fatal("could not init memcached cache")
		}
	}
}

var memcached *memcache.Client

const (
	KeySessions  = "session"
	KeyStateData = "state_data"
)

func memCacheStore(key string, claims model.UserClaims) error {
	memCachedClaims := config.Get().SessionStorage.MemCachedClaims
	if memCachedClaims == nil {
		memCachedClaims = config.DefaultMemCachedClaims
	}
	var values [][]byte
	for k, cls := range memCachedClaims {
		var value string
		var ok bool
		for _, cl := range cls {
			value, ok = claims.GetForMemCache(cl)
			if ok {
				break
			}
		}
		if value != "" {
			values = append(values, []byte(fmt.Sprintf("%s=%s", k, value)))
		}
	}
	value := bytes.Join(values, []byte("\r\n"))
	return errors.WithStack(
		memcached.Set(
			&memcache.Item{
				Key:        key,
				Value:      value,
				Expiration: int32(config.Get().SessionStorage.TTL),
			},
		),
	)
}

func SetSession(key string, value model.UserClaims) error {
	if memcached != nil {
		if err := memCacheStore(key, value); err != nil {
			return err
		}
	}
	return errors.WithStack(
		fedcache.Set(
			fedcache.Key(KeySessions, key), value, time.Duration(config.Get().SessionStorage.TTL)*time.Second,
		),
	)
}

func GetSession(key string, target *model.UserClaims) (bool, error) {
	return fedcache.Get(fedcache.Key(KeySessions, key), target)
}

func Set(subCache, key string, value any, ttl time.Duration) error {
	return errors.WithStack(fedcache.Set(fedcache.Key(subCache, key), value, ttl))
}

func Get(subCache, key string, target any) (bool, error) {
	return fedcache.Get(fedcache.Key(subCache, key), target)
}
