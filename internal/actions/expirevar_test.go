package actions

import (
	"errors"
	"strings"
	"testing"
)

func TestExpirevar(t *testing.T) {
	t.Parallel()
	a, err := Get("expirevar")
	if err != nil {
		t.Error("failed to get setvar action")
	}

	t.Run("no arguments", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "")
		if !errors.Is(err, ErrMissingArguments) {
			t.Errorf("expected error ErrMissingArguments, got %v", err)
		}
	})

	t.Run("invalid collection", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "INVALID.test=60")
		if !strings.Contains(err.Error(), "invalid collection, available collections are: ") {
			t.Errorf("expected error 'invalid collection...', got %v", err)
		}
	})

	t.Run("missing variable name", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "IP.=60")
		if !errors.Is(err, ErrInvalidKVArguments) {
			t.Errorf("expected error ErrInvalidKVArguments, got %v", err)
		}
	})

	t.Run("missing ttl", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "IP.test=")
		if !strings.Contains(err.Error(), "invalid TTL, must be a positive integer") {
			t.Errorf("expected error 'missing TTL value', got %v", err)
		}
	})

	t.Run("missing ttl", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "IP.test=-1")
		if !strings.Contains(err.Error(), "invalid TTL, must be a positive integer") {
			t.Errorf("expected error 'missing TTL value', got %v", err)
		}
	})

	t.Run("missing ttl", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "IP.test=0")
		if !strings.Contains(err.Error(), "invalid TTL, must be a positive integer") {
			t.Errorf("expected error 'missing TTL value', got %v", err)
		}
	})

	t.Run("valid input", func(t *testing.T) {
		t.Parallel()
		err := a.Init(nil, "TX.testvar=60")
		if err != nil {
			t.Errorf("unexpected error for valid input, got %v", err)
		}
	})
}
