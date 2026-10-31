// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package conformance

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

type suite struct {
	client *http.Client
	base   string
}

type testPlan struct {
	ID      string       `json:"id"`
	Modules []planModule `json:"modules"`
}

type planModule struct {
	TestModule string          `json:"testModule"`
	Variant    json.RawMessage `json:"variant"`
}

type moduleInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

func newSuite(t *testing.T, base string) *suite {
	if base[len(base)-1] != '/' {
		base += "/"
	}
	s := &suite{
		base: base,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
	// The suite takes about a minute to start.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		err := s.do(http.MethodGet, "api/runner/available", nil, nil, nil)
		if err == nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("suite not ready: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}

func (s *suite) do(method, path string, query url.Values, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	u := s.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, data)
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = data
		return nil
	}
	return json.Unmarshal(data, out)
}

func (s *suite) createPlan(name string, variant json.RawMessage, config any) (testPlan, error) {
	var p testPlan
	err := s.do(http.MethodPost, "api/plan", url.Values{"planName": {name}, "variant": {string(variant)}}, config, &p)
	return p, err
}

func (s *suite) createModule(plan, module string, variant json.RawMessage) (string, error) {
	q := url.Values{"test": {module}, "plan": {plan}}
	if len(variant) > 0 && string(variant) != "null" {
		q.Set("variant", string(variant))
	}
	var created struct {
		ID string `json:"id"`
	}
	err := s.do(http.MethodPost, "api/runner", q, nil, &created)
	return created.ID, err
}

func (s *suite) info(id string) (moduleInfo, error) {
	var info moduleInfo
	err := s.do(http.MethodGet, "api/info/"+id, nil, nil, &info)
	return info, err
}

// waitStatus waits until the module has one of the statuses, which is a regular expression.
func (s *suite) waitStatus(id, statuses string, timeout time.Duration) (moduleInfo, bool) {
	re := regexp.MustCompile("^(" + statuses + ")$")
	deadline := time.Now().Add(timeout)
	for {
		info, err := s.info(id)
		if err == nil && re.MatchString(info.Status) {
			return info, true
		}
		if time.Now().After(deadline) {
			return info, false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (s *suite) stop(id string) error {
	return s.do(http.MethodDelete, "api/runner/"+id, nil, nil, nil)
}

// save writes the suite info and log of the module in dir.
func (s *suite) save(id, dir string) error {
	for name, path := range map[string]string{"info.json": "api/info/" + id, "log.json": "api/log/" + id} {
		var data []byte
		if err := s.do(http.MethodGet, path, nil, nil, &data); err != nil {
			return err
		}
		if err := os.WriteFile(dir+"/"+name, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}
