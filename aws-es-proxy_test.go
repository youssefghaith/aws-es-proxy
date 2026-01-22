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
	req *http.Request
}

func (c *captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	body := io.NopCloser(bytes.NewBufferString(`{}`))
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
		Header:     make(http.Header),
		Request:    req,
	}, nil
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
	if rt.req == nil {
		t.Fatalf("expected proxied request to be captured")
	}
	if rt.req.Header.Get("Authorization") == "" {
		t.Fatalf("expected Authorization header to be set")
	}
	if rt.req.Header.Get("X-Amz-Date") == "" {
		t.Fatalf("expected X-Amz-Date header to be set")
	}
	expectedHash := sha256Hex([]byte{})
	if got := rt.req.Header.Get("X-Amz-Content-Sha256"); got != "" && got != expectedHash {
		t.Fatalf("expected X-Amz-Content-Sha256 to be %s when set", expectedHash)
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
