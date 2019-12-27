package proxy

import (
	"bytes"
	"encoding/json"
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
	Jwks   *authn.Jwks
	Policy *authz.OPAPolicy
	Tokens *token.Local

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
			req.Body = ioutil.NopCloser(bytes.NewReader(payload))
		}

		claims := make(map[string]interface{})
		if token != "" {
			var err error
			claims, err = s.Jwks.GetClaims(token)
			if err != nil {
				if err == authn.ErrCannotVerifyJSONWebToken || err == authn.ErrJSONWebTokenMissingIssuer {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
		}

		if !s.Policy.IsAllowed(req.Context(), s.evalInput(claims, req, payload)) {
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

func (s *Inbound) evalInput(claims map[string]interface{}, req *http.Request, payload []byte) authz.EvalInput {
	src := authz.Source{}

	if v, ok := claims["sub"]; ok {
		src.Identity = v.(string)
	}
	if v, ok := claims["iss"]; ok {
		src.Issuer = v.(string)
	}
	if v, ok := claims["aud"]; ok {
		// Only support single audience now
		auds := v.([]interface{})
		if len(auds) > 0 {
			src.Audience = auds[0].(string)
		}
	}

	var b map[string]interface{}
	if payload != nil {
		if err := json.Unmarshal(payload, &b); err != nil {
			s.Logger.Errorw("request payload cannot be unmarshalled", zap.Error(err))
		}
	}

	r := authz.PartialRequest{
		Method:        req.Method,
		Host:          req.Host,
		Path:          req.RequestURI,
		ContentLength: req.ContentLength,
		RemoteAddr:    req.RemoteAddr,
		Header:        req.Header,
		Body:          b,
	}

	return authz.EvalInput{
		Source:  src,
		Request: r,
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
