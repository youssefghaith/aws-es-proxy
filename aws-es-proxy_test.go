package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

type captureRoundTripper struct {
	mu  sync.Mutex
	req *http.Request
}

func (c *captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.req = req
	c.mu.Unlock()
	body := io.NopCloser(bytes.NewBufferString(`{}`))
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (c *captureRoundTripper) getReq() *http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.req
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	original, had := os.LookupEnv(key)
	if value == "" {
		_ = os.Unsetenv(key)
	} else {
		_ = os.Setenv(key, value)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, original)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func TestParseEndpointAmazonAWS(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		region   string
		service  string
	}{
		{"es", "https://test.us-west-2.es.amazonaws.com", "us-west-2", "es"},
		{"aoss", "https://test.us-west-2.aoss.amazonaws.com", "us-west-2", "aoss"},
		{"nonaws", "https://elastic.example.com", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newProxy(tc.endpoint, false, false, false, false, 15, false, "", "", "", false, "", "")
			if err := p.parseEndpoint(); err != nil {
				t.Fatalf("parseEndpoint failed: %v", err)
			}
			if p.region != tc.region || p.service != tc.service {
				t.Fatalf("got region=%q service=%q", p.region, p.service)
			}
		})
	}
}

func TestServeHTTPAddsAuthorizationHeader(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")

	p := newProxy(
		"https://us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"disabled",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	rt := &captureRoundTripper{}
	p.httpClient.Transport = rt

	req := httptest.NewRequest(http.MethodGet, "http://localhost:9200/_cat/indices?v", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}
	capturedReq := rt.getReq()
	if capturedReq == nil {
		t.Fatalf("expected proxied request to be captured")
	}
	if capturedReq.Header.Get("Authorization") == "" {
		t.Fatalf("expected Authorization header to be set")
	}
	if capturedReq.Header.Get("X-Amz-Date") == "" {
		t.Fatalf("expected X-Amz-Date header to be set")
	}
	expectedHash := sha256Hex([]byte{})
	if got := capturedReq.Header.Get("X-Amz-Content-Sha256"); got != "" && got != expectedHash {
		t.Fatalf("expected X-Amz-Content-Sha256 to be %s when set", expectedHash)
	}
}

func TestBasicAuthRequired(t *testing.T) {
	p := newProxy(
		"https://test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		true,
		"user",
		"pass",
		"Realm",
		false,
		"",
		"",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}
	p.httpClient.Transport = &captureRoundTripper{}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:9200/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBasicAuthSuccess(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")

	p := newProxy(
		"https://test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		true,
		"user",
		"pass",
		"Realm",
		false,
		"",
		"",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}
	p.httpClient.Transport = &captureRoundTripper{}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:9200/", nil)
	req.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestIMDSDisabledSetsEnv(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")
	setEnv(t, "AWS_EC2_METADATA_DISABLED", "")
	setEnv(t, "AWS_EC2_METADATA_V1_DISABLED", "")

	p := newProxy(
		"https://us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"disabled",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	if _, err := p.getCredentials(context.Background()); err != nil {
		t.Fatalf("getCredentials failed: %v", err)
	}

	if os.Getenv("AWS_EC2_METADATA_DISABLED") != "true" {
		t.Fatalf("expected AWS_EC2_METADATA_DISABLED to be true")
	}
	if os.Getenv("AWS_EC2_METADATA_V1_DISABLED") != "true" {
		t.Fatalf("expected AWS_EC2_METADATA_V1_DISABLED to be true")
	}
}

func TestIMDSEnvRequired(t *testing.T) {
	setEnv(t, "AWS_EC2_METADATA_DISABLED", "")
	setEnv(t, "AWS_EC2_METADATA_V1_DISABLED", "")

	p := newProxy(
		"https://test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"required",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	if os.Getenv("AWS_EC2_METADATA_DISABLED") != "" {
		t.Fatalf("expected AWS_EC2_METADATA_DISABLED unset")
	}
	if os.Getenv("AWS_EC2_METADATA_V1_DISABLED") != "true" {
		t.Fatalf("expected AWS_EC2_METADATA_V1_DISABLED true")
	}
}

func TestIMDSEnvOptional(t *testing.T) {
	setEnv(t, "AWS_EC2_METADATA_DISABLED", "true")
	setEnv(t, "AWS_EC2_METADATA_V1_DISABLED", "true")

	p := newProxy(
		"https://test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"optional",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	if os.Getenv("AWS_EC2_METADATA_DISABLED") != "" {
		t.Fatalf("expected AWS_EC2_METADATA_DISABLED unset")
	}
	if os.Getenv("AWS_EC2_METADATA_V1_DISABLED") != "" {
		t.Fatalf("expected AWS_EC2_METADATA_V1_DISABLED unset")
	}
}

// TestConcurrentCredentialAccess tests that concurrent requests don't race on credentials
func TestConcurrentCredentialAccess(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")

	p := newProxy(
		"https://vpc-test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"disabled",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	rt := &captureRoundTripper{}
	p.httpClient.Transport = rt

	var wg sync.WaitGroup
	const numGoroutines = 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://localhost:9200/_cat/indices?v", nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected status code: %d", rec.Code)
			}
		}()
	}

	wg.Wait()
}

// retryRoundTripper returns 403 on first call, then 200 on subsequent calls
type retryRoundTripper struct {
	callCount atomic.Int32
	mu        sync.Mutex
	requests  []*http.Request
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()

	count := r.callCount.Add(1)

	if count == 1 {
		// First call returns 403
		body := io.NopCloser(bytes.NewBufferString(`{"message": "The security token included in the request is expired"}`))
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       body,
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	// Subsequent calls return 200
	body := io.NopCloser(bytes.NewBufferString(`{}`))
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestRetryOn403 tests that the proxy retries on 403 responses
func TestRetryOn403(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")

	p := newProxy(
		"https://vpc-test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"disabled",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	rt := &retryRoundTripper{}
	p.httpClient.Transport = rt

	req := httptest.NewRequest(http.MethodGet, "http://localhost:9200/_cat/indices?v", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	// Should have retried and succeeded
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 after retry, got %d", rec.Code)
	}

	// Should have made 2 requests (initial + retry)
	if rt.callCount.Load() != 2 {
		t.Fatalf("expected 2 HTTP calls (initial + retry), got %d", rt.callCount.Load())
	}

	// After retry, credentials should be regenerated (not nil)
	// because getCredentials is called again on the retry
	p.credMu.RLock()
	creds := p.credentials
	p.credMu.RUnlock()
	if creds == nil {
		t.Fatalf("expected credentials to be regenerated after retry")
	}
}

// TestNoRetryOn403ForPOST tests that POST requests do NOT retry on 403
func TestNoRetryOn403ForPOST(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")

	p := newProxy(
		"https://vpc-test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"disabled",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	rt := &retryRoundTripper{}
	p.httpClient.Transport = rt

	// Use POST method which is not idempotent
	req := httptest.NewRequest(http.MethodPost, "http://localhost:9200/_bulk", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	// Should NOT have retried - return 403 directly
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 (no retry for POST), got %d", rec.Code)
	}

	// Should have made only 1 request (no retry)
	if rt.callCount.Load() != 1 {
		t.Fatalf("expected 1 HTTP call (no retry for POST), got %d", rt.callCount.Load())
	}
}

// TestInvalidateCredentials tests the invalidateCredentials helper
func TestInvalidateCredentials(t *testing.T) {
	setEnv(t, "AWS_ACCESS_KEY_ID", "test-access-key")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "test-secret-key")
	setEnv(t, "AWS_SESSION_TOKEN", "")

	p := newProxy(
		"https://vpc-test.us-west-2.es.amazonaws.com",
		false,
		false,
		false,
		false,
		15,
		false,
		"",
		"",
		"",
		false,
		"",
		"disabled",
	)
	if err := p.parseEndpoint(); err != nil {
		t.Fatalf("parseEndpoint failed: %v", err)
	}

	// First, get credentials to initialize them
	if _, err := p.getCredentials(context.Background()); err != nil {
		t.Fatalf("getCredentials failed: %v", err)
	}

	// Verify credentials are set
	p.credMu.RLock()
	if p.credentials == nil {
		p.credMu.RUnlock()
		t.Fatalf("expected credentials to be set")
	}
	p.credMu.RUnlock()

	// Invalidate credentials
	p.invalidateCredentials()

	// Verify credentials are nil
	p.credMu.RLock()
	if p.credentials != nil {
		p.credMu.RUnlock()
		t.Fatalf("expected credentials to be nil after invalidation")
	}
	p.credMu.RUnlock()
}
