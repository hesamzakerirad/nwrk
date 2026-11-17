// Package exit defines the process exit codes of nw.
//
// The codes follow the conventions of ping, grep and curl so scripts behave
// the way people expect.
package exit

import "errors"

const (
	// OK means the command ran and found no problem.
	OK = 0
	// Findings means the command ran and the target has a problem.
	Findings = 1
	// Failure means a usage error, or the tool could not run the measurement.
	Failure = 2
	// Interrupted means the user stopped the command (128 + SIGINT).
	Interrupted = 130
)

// Kind tells the two causes of exit code 2 apart in error output.
type Kind string

const (
	KindUsage     Kind = "usage"
	KindExecution Kind = "execution"
)

// Error carries an exit code through the command tree.
type Error struct {
	Code int
	Kind Kind
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Usage wraps an invalid flag, target or configuration.
func Usage(err error) error {
	return &Error{Code: Failure, Kind: KindUsage, Err: err}
}

// Execution wraps a failure of the tool itself.
func Execution(err error) error {
	return &Error{Code: Failure, Kind: KindExecution, Err: err}
}

// KindOf classifies err. Unknown errors count as usage errors, because
// those are the ones the command framework produces.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindUsage
}

// CodeOf returns the exit code for err.
func CodeOf(err error) int {
	if err == nil {
		return OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return Failure
}
