package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store 是 email 维度的本地凭证缓存。
//
// 设计要点：
//   - 每个缓存键一个 JSON 文件（<sha256 前 16 字节>.json），内容为完整的
//     凭证 map，权限 0600；
//   - 原子写（临时文件 + rename），进程崩溃不产生半截文件；
//   - per-key 互斥锁，配合调用方的 double-check 实现刷新 single-flight，
//     避免同一凭证的并发请求各自发起刷新（rolling refresh 只允许一个赢家）。
type Store struct {
	dir string

	mu       sync.Mutex
	keyLocks map[string]*keyLock
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

// NewStore 创建缓存存储并确保目录存在。
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create credential cache dir: %w", err)
	}
	return &Store{dir: dir, keyLocks: make(map[string]*keyLock)}, nil
}

// Dir 返回缓存目录（供日志展示）。
func (s *Store) Dir() string { return s.dir }

// path 返回某缓存键对应的文件路径。
func (s *Store) path(key string) string {
	return filepath.Join(s.dir, key+".json")
}

// Load 读取缓存凭证；不存在或损坏时返回 false。
func (s *Store) Load(key string) (*Credential, bool) {
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		return nil, false
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, false
	}
	cred, err := FromMap(payload)
	if err != nil {
		return nil, false
	}
	if cred.CacheKey() != key {
		// 缓存文件与请求键不一致（例如 email 字段被手工改动），视为未命中。
		return nil, false
	}
	return cred, true
}

// Save 原子写回缓存（含刷新后的 token 轮换链）。
func (s *Store) Save(key string, cred *Credential) error {
	if cred == nil || cred.Raw == nil {
		return fmt.Errorf("refuse to persist empty credential")
	}
	data, err := json.MarshalIndent(cred.Raw, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credential cache: %w", err)
	}

	tmp := s.path(key) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write credential cache: %w", err)
	}
	if err := os.Rename(tmp, s.path(key)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit credential cache: %w", err)
	}
	return nil
}

// Stamp 在缓存文件里记录最近一次刷新时间（可观测性，非功能性）。
func (s *Store) Stamp(key string, cred *Credential, at time.Time) {
	if cred.Raw == nil {
		return
	}
	cred.Raw["_oai_mini_proxy_refreshed_at"] = at.UTC().Format(time.RFC3339)
}

// WithLock 在该缓存键的互斥锁内执行 fn，配合调用方 double-check 实现 single-flight。
func (s *Store) WithLock(key string, fn func() error) error {
	lock := s.acquire(key)
	defer s.release(key, lock)

	lock.mu.Lock()
	defer lock.mu.Unlock()
	return fn()
}

func (s *Store) acquire(key string) *keyLock {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, ok := s.keyLocks[key]
	if !ok {
		lock = &keyLock{}
		s.keyLocks[key] = lock
	}
	lock.refs++
	return lock
}

func (s *Store) release(key string, lock *keyLock) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock.refs--
	if lock.refs <= 0 {
		delete(s.keyLocks, key)
	}
}
