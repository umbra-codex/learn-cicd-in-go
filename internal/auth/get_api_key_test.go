package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "my-secret" {
		t.Errorf("expected key %q, got %q", "my-secret-key", got)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	got, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty key, got %q", got)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := map[string]string{
		"wrong scheme": "Bearer my-secret-key",
		"no key":       "ApiKey",
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", value)

			got, err := GetAPIKey(headers)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if errors.Is(err, ErrNoAuthHeaderIncluded) {
				t.Errorf("expected malformed header error, got ErrNoAuthHeaderIncluded")
			}
			if got != "" {
				t.Errorf("expected empty key, got %q", got)
			}
		})
	}
}
