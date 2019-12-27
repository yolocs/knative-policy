package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/yolocs/knative-policy/pkg/utils"
	"gopkg.in/square/go-jose.v2/jwt"

	jose "gopkg.in/square/go-jose.v2"
)

var jwksRefreshInterval time.Duration = 24 * time.Hour

var (
	ErrCannotVerifyJSONWebToken  = fmt.Errorf("cannot verify the JWT")
	ErrJSONWebTokenMissingIssuer = fmt.Errorf("cannot find issuer from the JWT")
)

type issuer struct {
	Iss string `json:"iss,omitempty"`
}

// TODO: to also support public key
type Jwks struct {
	data map[string]*jose.JSONWebKeySet
	mux  *sync.RWMutex

	fc *utils.FileCache
}

func NewJwks(filePath string) (*Jwks, error) {
	j := &Jwks{data: make(map[string]*jose.JSONWebKeySet), mux: &sync.RWMutex{}}
	fc, err := utils.NewFileCache(filePath, jwksRefreshInterval, j.unmarshal)
	if err != nil {
		return nil, err
	}
	j.fc = fc
	return j, nil
}

func (j *Jwks) Start(ctx context.Context) {
	j.fc.Start(ctx)
}

func (j *Jwks) GetClaims(rawToken string) (map[string]interface{}, error) {
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return nil, ErrCannotVerifyJSONWebToken
	}

	issuer := &issuer{}
	if err := token.UnsafeClaimsWithoutVerification(issuer); err != nil {
		return nil, ErrCannotVerifyJSONWebToken
	}
	if _, allowIss := j.data[issuer.Iss]; !allowIss {
		return nil, ErrJSONWebTokenMissingIssuer
	}

	k, foundKey := j.findKey(issuer.Iss, token)
	if !foundKey {
		return nil, ErrCannotVerifyJSONWebToken
	}

	claims := make(map[string]interface{})
	if err := token.Claims(k, &claims); err != nil {
		return nil, ErrCannotVerifyJSONWebToken
	}

	if expRaw, ok := claims["exp"]; ok {
		exp := time.Unix(int64(expRaw.(float64)), 0)
		if exp.Before(time.Now()) {
			return nil, ErrCannotVerifyJSONWebToken
		}
	}

	return claims, nil
}

func (j *Jwks) findKey(iss string, t *jwt.JSONWebToken) (jose.JSONWebKey, bool) {
	j.mux.RLock()
	defer j.mux.RUnlock()

	ks := j.data[iss]
	if len(ks.Keys) == 0 {
		return jose.JSONWebKey{}, false
	}
	for _, h := range t.Headers {
		usableKeys := ks.Key(h.KeyID)
		if len(usableKeys) != 0 {
			return usableKeys[0], true
		}
	}
	// If kid is found, try the first key.
	return ks.Keys[0], true
}

func (j *Jwks) unmarshal(data []byte) error {
	var raw map[string][]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	r := make(map[string]*jose.JSONWebKeySet)
	for iss, ksJSON := range raw {
		ks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
		for _, kJSON := range ksJSON {
			// This is a workaround
			kBytes, err := json.Marshal(kJSON)
			if err != nil {
				return err
			}
			k := &jose.JSONWebKey{}
			if err := k.UnmarshalJSON(kBytes); err != nil {
				return err
			}
			ks.Keys = append(ks.Keys, *k)
		}
		r[iss] = ks
	}

	j.mux.Lock()
	defer j.mux.Unlock()

	j.data = r
	return nil
}
