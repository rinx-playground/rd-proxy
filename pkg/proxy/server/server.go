package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/rego"
	"github.com/rancher/remotedialer"
	"github.com/rinx-playground/rd-proxy/pkg/config"
)

const defaultProxyPolicy = `
package proxy.policy

import rego.v1

default allow := false

allow if {
	input.method == "GET"
}
`

type Config struct {
	Addr   string
	Policy string
}

type conn struct {
	port string
}

type server struct {
	rds *remotedialer.Server

	conns map[string]*conn
	mu    *sync.RWMutex

	query rego.PreparedEvalQuery

	*Config
}

type Server interface {
	Start(ctx context.Context) error
}

func New(c *Config) (Server, error) {
	conns := make(map[string]*conn)

	s := &server{
		conns:  conns,
		mu:     &sync.RWMutex{},
		Config: c,
	}

	if s.Policy == "" {
		s.Policy = defaultProxyPolicy
	}

	s.rds = remotedialer.New(s.authorize, remotedialer.DefaultErrorWriter)

	return s, nil
}

func (s *server) Start(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.query, err = rego.New(
		rego.Query("x := data.proxy.policy.allow"),
		rego.Module("policy.rego", s.Policy),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}

	router := mux.NewRouter()
	router.Handle("/proxy-connect", s.rds)
	router.HandleFunc("/", s.handle)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				s.refreshConn()
			case <-ctx.Done():
				if err := ctx.Err(); err != context.Canceled {
					return
				}
			}
		}
	}()

	slog.Info("start server", "addr", s.Addr)

	return http.ListenAndServe(s.Addr, router)
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	ok, err := s.validate(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error("failed to validate request", "error", err)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	id := r.Header.Get(config.ProxyIDHeader)

	conn, ok := s.lookupConn(id)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = net.JoinHostPort("127.0.0.1", conn.port)
		},
		Transport: &http.Transport{
			DialContext: s.rds.Dialer(id),
		},
	}

	slog.Info("bypass request", "service", id, "port", conn.port)

	rp.ServeHTTP(w, r)
}

func (s *server) lookupConn(id string) (*conn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conn, ok := s.conns[id]
	return conn, ok
}

func (s *server) refreshConn() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range s.conns {
		if !s.rds.HasSession(id) {
			delete(s.conns, id)
		}
	}
}

func (s *server) authorize(req *http.Request) (string, bool, error) {
	id := req.Header.Get(config.ProxyIDHeader)
	port := req.Header.Get(config.ProxyTargetPortHeader)

	if id == "" || port == "" {
		return "", false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.conns[id]; ok {
		// duplicated id
		return id, false, nil
	}

	s.conns[id] = &conn{
		port: port,
	}

	return id, true, nil
}

func (s *server) validate(r *http.Request) (bool, error) {
	input := map[string]interface{}{
		"method":     r.Method,
		"header":     r.Header,
		"path":       r.URL.Path,
		"remoteaddr": r.RemoteAddr,
	}

	rs, err := s.query.Eval(r.Context(), rego.EvalInput(input))
	if err != nil {
		return false, err
	}
	if len(rs) == 0 {
		return false, errors.New("no result")
	}

	res, ok := rs[0].Bindings["x"].(bool)
	if !ok {
		return false, errors.New("failed to cast")
	}

	return res, nil
}
