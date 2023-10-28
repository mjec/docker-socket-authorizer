package internal

import (
	"io"
	"net/http"
	"strings"
)

type request struct {
	Uri        string      `json:"uri"`
	RemoteAddr string      `json:"remote_addr"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
}

type Input struct {
	Request request `json:"request"`
}

func MakeInput(r *http.Request) (Input, error) {
	lowerHeaders := make(http.Header, len(r.Header))
	for k, v := range r.Header {
		lowerHeaders[strings.ToLower(k)] = v
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return Input{}, err
	}

	return Input{
		request{
			Uri:        r.RequestURI,
			RemoteAddr: r.RemoteAddr,
			Headers:    lowerHeaders,
			Body:       string(body),
		},
	}, nil
}
