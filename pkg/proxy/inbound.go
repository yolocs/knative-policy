package proxy

import (
	"io/ioutil"
	"net/http"

	"github.com/yolocs/knative-policy/pkg/authn"
	"github.com/yolocs/knative-policy/pkg/authz"
	"github.com/yolocs/knative-policy/pkg/token"
	"go.uber.org/zap"
)

var (
	AuthorizationHeader          = http.CanonicalHeaderKey("Knative-Proxy-Auhtorization")
	ForwardedAuthorizationHeader = http.CanonicalHeaderKey("Knative-Proxy-Forwarded-For")
	IdentityHintHeader           = http.CanonicalHeaderKey("Knative-Proxy-Identity-Hint")
)

type Inbound struct {
	Jwks     *authn.Jwks
	Policies *authz.Policies
	Tokens   *token.Local

	ApplyPolicyOnPayload bool
	ReplyWithIdentity    bool

	Logger *zap.SugaredLogger
}

func (s *Inbound) Handler(next http.Handler) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		s.Logger.Infof("Receiver request: %s %s", req.Method, req.RequestURI)

		token := req.Header.Get(ForwardedAuthorizationHeader)
		if token == "" {
			token = req.Header.Get(AuthorizationHeader)
		}

		var payload []byte
		if s.ApplyPolicyOnPayload {
			var err error
			payload, err = ioutil.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
		}

		if token == "" {
			if !s.Policies.IsAllowed("", req.Header, payload) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		claims, err := s.Jwks.GetClaims(token)
		if err != nil {
			if err == authn.ErrCannotVerifyJSONWebToken || err == authn.ErrJSONWebTokenMissingIssuer {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		sub := claims["sub"].(string)
		if !s.Policies.IsAllowed(sub, req.Header, payload) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Remove the authorization header.
		req.Header.Del(AuthorizationHeader)
		// if s.ReplyWithIdentity {
		// 	// Currently not used.
		// 	w.Header().Set(IdentityHintHeader, sub)
		// }

		next.ServeHTTP(w, req)
	}
}

func (s *Inbound) ModifyReponse(resp *http.Response) error {
	// Only returns identity if request was successful and
	// there is a response body.
	if s.ReplyWithIdentity && resp.StatusCode < 400 {
		if resp.ContentLength > 0 {
			if t, ok := s.Tokens.AudiencelessToken(); ok {
				resp.Header.Set(ForwardedAuthorizationHeader, t)
			}
		}
	}
	return nil
}
