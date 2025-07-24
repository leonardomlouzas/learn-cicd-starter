package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		header http.Header
		want   string
		err    error
	}{
		"valid": {
			header: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			want:   "my-secret-key",
			err:    nil,
		},
		"no auth header": {
			header: http.Header{},
			want:   "",
			err:    ErrNoAuthHeaderIncluded,
		},
		"malformed - wrong scheme": {
			header: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			want:   "",
			err:    errors.New("malformed authorization header"),
		},
		"malformed - no space": {
			header: http.Header{"Authorization": []string{"ApiKeymy-secret-key"}},
			want:   "",
			err:    errors.New("malformed authorization header"),
		},
		"malformed - only one part": {
			header: http.Header{"Authorization": []string{"ApiKey"}},
			want:   "",
			err:    errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.header)
			if got != tc.want {
				t.Fatalf("GetAPIKey() got key = %v, want %v", got, tc.want)
			}
			if !errors.Is(err, tc.err) && (err == nil || tc.err == nil || err.Error() != tc.err.Error()) {
				t.Fatalf("GetAPIKey() got error = %v, want %v", err, tc.err)
			}
		})
	}
}