package hcloudplus

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
)

// ErrorCode is the machine-readable error identifier returned by the Hetzner
// private API. The private API uses numeric codes in most cases, while the
// public API uses string codes; we keep this as a string so we can hold
// either.
type ErrorCode string

// Well-known codes observed so far. Extend as new ones are seen.
const (
	ErrorCodeUnauthorized ErrorCode = "unauthorized"
	ErrorCodeForbidden    ErrorCode = "forbidden"
	ErrorCodeNotFound     ErrorCode = "not_found"
	ErrorCodeRateLimit    ErrorCode = "rate_limit_exceeded"
	ErrorCodeInvalidInput ErrorCode = "invalid_input"
	ErrorCodeServerError  ErrorCode = "server_error"
)

// Error is the error type returned by the client when the API responds with a
// non-2xx status. It mirrors hcloud.Error so callers familiar with hcloud-go
// feel at home.
type Error struct {
	Code     ErrorCode
	Message  string
	Response *http.Response
}

func (e Error) Error() string {
	if e.Code != "" && e.Message != "" {
		return fmt.Sprintf("hcloudplus: %s (%s)", e.Message, e.Code)
	}
	if e.Message != "" {
		return "hcloudplus: " + e.Message
	}
	return fmt.Sprintf("hcloudplus: http %d", e.Response.StatusCode)
}

// IsError reports whether err is a hcloudplus.Error with one of the given
// codes. Matches hcloud.IsError in spirit; walks wrapped errors via
// errors.As so callers can wrap freely.
func IsError(err error, codes ...ErrorCode) bool {
	var e Error
	if !errors.As(err, &e) {
		return false
	}
	return slices.Contains(codes, e.Code)
}

// errorResponseBody is the server-side envelope.
//
//	{"error":{"code":403,"message":"access denied"}}
//
// `code` can be either a number (most private endpoints) or a string
// (borrowed from the public API). We accept both.
type errorResponseBody struct {
	Error struct {
		Code    json.RawMessage `json:"code"`
		Message string          `json:"message"`
	} `json:"error"`
}

func parseErrorResponse(resp *http.Response, body []byte) error {
	out := Error{Response: resp}
	var env errorResponseBody
	if len(body) > 0 && json.Unmarshal(body, &env) == nil {
		out.Message = env.Error.Message
		out.Code = decodeErrorCode(env.Error.Code, resp.StatusCode)
	}
	if out.Code == "" {
		out.Code = statusToCode(resp.StatusCode)
	}
	return out
}

func decodeErrorCode(raw json.RawMessage, status int) ErrorCode {
	if len(raw) == 0 {
		return statusToCode(status)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return ErrorCode(s)
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return statusToCode(n)
	}
	return statusToCode(status)
}

func statusToCode(status int) ErrorCode {
	switch status {
	case http.StatusUnauthorized:
		return ErrorCodeUnauthorized
	case http.StatusForbidden:
		return ErrorCodeForbidden
	case http.StatusNotFound:
		return ErrorCodeNotFound
	case http.StatusTooManyRequests:
		return ErrorCodeRateLimit
	case http.StatusUnprocessableEntity, http.StatusBadRequest:
		return ErrorCodeInvalidInput
	}
	if status >= 500 {
		return ErrorCodeServerError
	}
	return ""
}
