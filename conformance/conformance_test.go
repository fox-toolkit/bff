// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

// Package conformance runs the client test plans of the OpenID Foundation conformance suite against the BFF.
package conformance

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/rp"
	goredis "github.com/redis/go-redis/v9"
)

type plan struct {
	name         string // plans/<name>.json
	key          bool   // for private_key_jwt
	storeOnly    bool
	resourceOnly bool
	noLogin      string // module that runs without login
	options      func(module string) []rp.FrontendOption
	run          func(b *browser, module string)
}

var plans = []plan{
	{name: "fapi2", key: true, options: fapi2, run: get("/api/open-banking/v1.1/accounts")},
	{
		name:    "fapi2-message-signing",
		key:     true,
		options: func(m string) []rp.FrontendOption { return append(fapi2(m), rp.WithRequestObject(true)) },
		run:     get("/api/open-banking/v1.1/accounts"),
	},
	{name: "oidcc-basic", options: userInfo},
	{name: "oidcc-config", noLogin: discoveryModule, options: configOptions, run: configRun},
	// It includes the modules of the Basic and Config plans.
	{name: "oidcc-comprehensive", noLogin: discoveryModule, options: configOptions, run: configRun},
	{name: "oidcc-refresh", resourceOnly: true, options: userInfo, run: get("/api/userinfo")},
	{
		name:      "logout-backchannel",
		storeOnly: true,
		// The client registers no id_token_signed_response_alg, so RS256 is expected (OIDC Core 3.1.3.7).
		options: func(m string) []rp.FrontendOption { return append(userInfo(m), rp.WithSigningAlgorithms("RS256")) },
		run:     (*browser).logoutModule,
	},
	// The RP-initiated logout plan also sends back-channel logout requests, which require a store.
	{name: "logout-rp-initiated", storeOnly: true, options: userInfo, run: (*browser).logoutModule},
}

func fapi2(string) []rp.FrontendOption {
	return []rp.FrontendOption{
		rp.WithPushedAuthorization(rp.PushedAuthorizationRequired),
		rp.WithDPoP(true),
		rp.WithSigningAlgorithms("PS256", "ES256", "EdDSA"),
	}
}

func userInfo(string) []rp.FrontendOption {
	return []rp.FrontendOption{rp.WithUserInfo(true)}
}

// This module finishes when the client fetches the discovery, and fails on any later request.
const discoveryModule = "oidcc-client-test-discovery-openid-config"

func configOptions(module string) []rp.FrontendOption {
	// This module finishes when the client fetches the key set, and fails on any later request.
	if module == "oidcc-client-test-discovery-jwks-uri-keys" {
		return nil
	}
	return userInfo(module)
}

func configRun(b *browser, module string) {
	// The provider rotates its keys after the first ID token.
	if module == "oidcc-client-test-signing-key-rotation" {
		b.login()
	}
}

func get(p string) func(b *browser, module string) {
	return func(b *browser, _ string) { b.get(p) }
}

func (b *browser) logoutModule(string) { b.logout() }

type setup struct {
	store    string
	resource bool
}

func (s setup) String() string {
	if s.resource {
		return s.store + "-resource"
	}
	return s.store
}

type planFile struct {
	PlanName string                    `json:"planName"`
	Variant  json.RawMessage           `json:"variant"`
	Config   map[string]any            `json:"config"`
	Expected map[string]expectedResult `json:"expected"`
}

type expectedResult struct {
	Result string `json:"result"`
	Note   string `json:"note"`
}

func TestConformance(t *testing.T) {
	suiteURL := os.Getenv("BFF_CONFORMANCE_SUITE")
	if suiteURL == "" {
		t.Skip("BFF_CONFORMANCE_SUITE not set")
	}
	s := newSuite(t, suiteURL)

	stores := []string{"stateless", "memory"}
	var rdb *goredis.Client
	if addr := os.Getenv("BFF_REDIS_ADDR"); addr != "" {
		rdb = goredis.NewClient(&goredis.Options{Addr: addr})
		t.Cleanup(func() { _ = rdb.Close() })
		stores = append(stores, "redis")
	}

	for _, p := range plans {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("plans", p.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var file planFile
			if err := json.Unmarshal(data, &file); err != nil {
				t.Fatal(err)
			}
			for _, store := range stores {
				for _, res := range []bool{false, true} {
					st := setup{store: store, resource: res}
					if (p.storeOnly && store == "stateless") || (p.resourceOnly && !res) {
						continue
					}
					t.Run(st.String(), func(t *testing.T) {
						t.Parallel()
						r := &run{suite: s, plan: p, file: file, setup: st, redis: rdb, dir: filepath.Join("results", p.name, st.String())}
						r.start(t)
					})
				}
			}
		})
	}
}

type run struct {
	suite   *suite
	redis   *goredis.Client
	handler atomic.Pointer[http.Handler]
	file    planFile
	key     *ecdsa.PrivateKey
	setup   setup
	plan    plan
	dir     string
	baseURL string
	issuer  string
}

func (r *run) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := r.handler.Load()
	if h == nil {
		http.Error(w, "no bff", http.StatusServiceUnavailable)
		return
	}
	(*h).ServeHTTP(w, req)
}

func (r *run) start(t *testing.T) {
	if err := os.RemoveAll(r.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// The suite sends the back-channel logout requests to host.docker.internal, so the BFF listens on every interface.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	r.baseURL = fmt.Sprintf("http://localhost:%d", port)

	alias := "bff-" + r.plan.name + "-" + r.setup.String()
	r.issuer = r.suite.base + "test/a/" + alias + "/"
	config := maps.Clone(r.file.Config)
	config["alias"] = alias
	client := maps.Clone(config["client"].(map[string]any))
	config["client"] = client
	client["redirect_uri"] = r.baseURL + "/bff/callback"
	client["post_logout_redirect_uri"] = r.baseURL + "/"
	if r.setup.store != "stateless" {
		client["backchannel_logout_uri"] = fmt.Sprintf("http://host.docker.internal:%d/bff/backchannel", port)
	}
	if r.plan.key {
		r.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		client["jwks"] = map[string]any{"keys": []any{publicJWK(r.key)}}
	}

	tp, err := r.suite.createPlan(r.file.PlanName, r.file.Variant, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%splan-detail.html?plan=%s", r.suite.base, tp.ID)

	var summary strings.Builder
	ran := 0
	for _, m := range tp.Modules {
		t.Run(m.TestModule, func(t *testing.T) {
			ran++
			got := r.module(t, tp.ID, m.TestModule, m.Variant)
			want := cmp.Or(r.file.Expected[m.TestModule].Result, "PASSED")
			fmt.Fprintf(&summary, "%-75s %s\n", m.TestModule, got)
			if got != want {
				t.Errorf("result %s, want %s, see %s", got, want, filepath.Join(r.dir, m.TestModule))
			}
		})
	}
	if err := os.WriteFile(filepath.Join(r.dir, "summary.txt"), []byte(summary.String()), 0o600); err != nil {
		t.Error(err)
	}
	if ran < len(tp.Modules) {
		return
	}
	for name := range r.file.Expected {
		if !slices.ContainsFunc(tp.Modules, func(m planModule) bool { return m.TestModule == name }) {
			t.Errorf("expected result for %s, which is not in the plan", name)
		}
	}
}

func (r *run) module(t *testing.T, plan, module string, variant json.RawMessage) string {
	dir := filepath.Join(r.dir, module)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	flow, err := os.Create(filepath.Join(dir, "flow.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	log, err := os.Create(filepath.Join(dir, "rp.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	id, err := r.suite.createModule(plan, module, variant)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.suite.waitStatus(id, "WAITING|FINISHED|INTERRUPTED", time.Minute); !ok {
		t.Fatal("module not started")
	}

	// A new BFF for each module, since each module has its own provider.
	client, _ := r.file.Config["client"].(map[string]any)
	h, err := newBFF(bffConfig{
		plan:     r.plan,
		module:   module,
		setup:    r.setup,
		issuer:   r.issuer,
		baseURL:  r.baseURL,
		clientID: stringValue(client["client_id"]),
		secret:   stringValue(client["client_secret"]),
		scopes:   strings.Fields(cmp.Or(stringValue(client["scope"]), "openid profile email")),
		key:      r.key,
		redis:    r.redis,
		log:      log,
	})
	if err != nil {
		_, _ = fmt.Fprintf(flow, "bff: %v\n", err)
	} else if module != r.plan.noLogin {
		r.handler.Store(&h)
		b := newBrowser(r.baseURL, flow)
		b.login()
		b.get("/bff/user")
		if r.plan.run != nil {
			r.plan.run(b, module)
		}
	}

	info, ok := r.suite.waitStatus(id, "FINISHED|INTERRUPTED", 30*time.Second)
	if !ok {
		_, _ = fmt.Fprintf(flow, "module still %s, stopped\n", info.Status)
		if err := r.suite.stop(id); err != nil {
			t.Error(err)
		}
		info, _ = r.suite.waitStatus(id, "FINISHED|INTERRUPTED", 10*time.Second)
	}
	r.handler.Store(nil)
	if err := r.suite.save(id, dir); err != nil {
		t.Error(err)
	}
	return cmp.Or(info.Result, info.Status)
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}
