package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestModelQueryPathEncodesName(t *testing.T) {
	got := modelQueryPath("/v1/model", "Phi-3 Mini 3.8B (Q4_K_M)")
	want := "/v1/model?name=Phi-3+Mini+3.8B+%28Q4_K_M%29"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestAPIRequestAddsServiceToken(t *testing.T) {
	tokenFile, err := os.CreateTemp(t.TempDir(), "service-token-*")
	if err != nil {
		t.Fatalf("create token file: %v", err)
	}
	if _, err := tokenFile.WriteString("test-token\n"); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if err := tokenFile.Close(); err != nil {
		t.Fatalf("close token file: %v", err)
	}

	t.Setenv("SERVICE_TOKEN_PATH", tokenFile.Name())

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()

	registryURL = server.URL
	_, code, err := apiDelete("/v1/model/delete?name=test")
	if err != nil {
		t.Fatalf("apiDelete failed: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("expected bearer token header, got %q", gotAuth)
	}
}

func TestAPIRequestOmitsEmptyServiceToken(t *testing.T) {
	t.Setenv("SERVICE_TOKEN_PATH", t.TempDir()+"/missing-token")

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()

	registryURL = server.URL
	_, code, err := apiPost("/v1/model/verify?name=test")
	if err != nil {
		t.Fatalf("apiPost failed: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if strings.TrimSpace(gotAuth) != "" {
		t.Fatalf("expected no authorization header, got %q", gotAuth)
	}
}
