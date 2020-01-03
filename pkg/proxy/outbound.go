package proxy

import (
	"io"
	"net/http"

	"github.com/yolocs/knative-policy/pkg/token"
	"go.uber.org/zap"
)

type Outbound struct {
	Tokens    *token.Local
	Transport http.RoundTripper
	Logger    *zap.SugaredLogger
}

func (s *Outbound) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Hostname() == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	s.Logger.Infof("Forwarding request: %s %s", req.Method, req.URL)

	if req.Host == "" {
		http.Error(w, "Only absolute URL is supported", http.StatusBadRequest)
		return
	}

	// Don't override application provided header.
	if req.Header.Get(AuthorizationHeader) == "" {
		s.Logger.Debug("No Knative token provided, attaching token...")
		t, ok := s.Tokens.FindToken(req.URL.Hostname())
		if !ok {
			s.Logger.Infof("No token found for request to %q; sending request anonymously", req.URL.Hostname())
		}
		req.Header.Set(AuthorizationHeader, t)
	}

	resp, err := s.Transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	origBody := resp.Body
	defer origBody.Close()

	if origBody != resp.Body {
		resp.Header.Del("Content-Length")
	}

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	if err := resp.Body.Close(); err != nil {
		s.Logger.Warnf("Can't close response body %v", err)
	}
}
