package image_test

import (
	"testing"

	"github.com/MonitOwl/measr/pkg/image"
)

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"./bin/ls", "/bin/ls"},
		{"bin/ls", "/bin/ls"},
		{"/bin/ls", "/bin/ls"},
		{"a/b/../c", "/a/c"},
		{"///foo//bar", "/foo/bar"},
		{".", "/"},
		{"", "/"},
		{"./etc/nginx/nginx.conf", "/etc/nginx/nginx.conf"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := image.NormalizePath(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsWhiteout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected bool
	}{
		{".wh.foo", true},
		{"dir/.wh.bar", true},
		{"a/b/c/.wh.deleted", true},
		{".wh..wh..opq", false},
		{"dir/.wh..wh..opq", false},
		{"regular_file", false},
		{"dir/regular_file", false},
		{"wh.foo", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := image.IsWhiteout(tt.input)
			if got != tt.expected {
				t.Errorf("IsWhiteout(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsOpaqueWhiteout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected bool
	}{
		{".wh..wh..opq", true},
		{"dir/.wh..wh..opq", true},
		{"a/b/c/.wh..wh..opq", true},
		{".wh.foo", false},
		{"dir/.wh.bar", false},
		{"regular.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := image.IsOpaqueWhiteout(tt.input)
			if got != tt.expected {
				t.Errorf("IsOpaqueWhiteout(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestWhiteoutOriginal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{".wh.foo", "/foo"},
		{"etc/.wh.passwd", "/etc/passwd"},
		{"./var/log/.wh.syslog", "/var/log/syslog"},
		{"usr/local/bin/.wh.app", "/usr/local/bin/app"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := image.WhiteoutOriginal(tt.input)
			if got != tt.expected {
				t.Errorf("WhiteoutOriginal(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
