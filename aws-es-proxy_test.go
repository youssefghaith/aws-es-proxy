package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
