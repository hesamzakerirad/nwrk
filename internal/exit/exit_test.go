package exit

import (
	"errors"
	"fmt"
	"testing"
)

func TestCodes(t *testing.T) {
	base := errors.New("boom")
	cases := []struct {
		name string
		err  error
		code int
		kind Kind
	}{
		{"nil", nil, OK, ""},
		{"usage", Usage(base), Failure, KindUsage},
		{"execution", Execution(base), Failure, KindExecution},
		{"wrapped", fmt.Errorf("ctx: %w", Execution(base)), Failure, KindExecution},
		{"foreign", base, Failure, KindUsage},
	}
	for _, c := range cases {
		if got := CodeOf(c.err); got != c.code {
			t.Errorf("%s: CodeOf = %d, want %d", c.name, got, c.code)
		}
		if c.err != nil {
			if got := KindOf(c.err); got != c.kind {
				t.Errorf("%s: KindOf = %q, want %q", c.name, got, c.kind)
			}
		}
	}
}

func TestPublishedValues(t *testing.T) {
	if OK != 0 || Findings != 1 || Failure != 2 || Interrupted != 130 {
		t.Error("exit codes are a public contract and must not change")
	}
}
