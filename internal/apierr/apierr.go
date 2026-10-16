// Package apierr carries errors that are safe to show to API clients.
// Any other error reaching the HTTP layer is reported as an internal error.
package apierr

import (
	"errors"
	"fmt"

	"github.com/contember/sonda/api"
)

type Error struct {
	Code    api.ErrorCode
	Message string
}

func (e *Error) Error() string {
	return string(e.Code) + ": " + e.Message
}

func New(code api.ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func NotFound(format string, args ...any) *Error {
	return New(api.CodeNotFound, format, args...)
}

func InvalidRequest(format string, args ...any) *Error {
	return New(api.CodeInvalidRequest, format, args...)
}

func InvalidQuery(format string, args ...any) *Error {
	return New(api.CodeInvalidQuery, format, args...)
}

func Upstream(format string, args ...any) *Error {
	return New(api.CodeUpstreamError, format, args...)
}

func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
