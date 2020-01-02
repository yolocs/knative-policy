package token

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yolocs/knative-policy/pkg/utils"
)

const (
	audiencelessTokenName string = "unscoped"
)

var tokenRefreshInterval time.Duration = 5 * time.Minute

type Local struct {
	tokenRootDir string
	data         *sync.Map

	fc []*utils.FileCache
}

func NewLocal(tokenRootDir string) (*Local, error) {
	l := &Local{
		data: &sync.Map{},
		fc:   []*utils.FileCache{},
	}

	subTokenDirs, err := ioutil.ReadDir(tokenRootDir)
	if err != nil {
		return nil, err
	}

	for _, sub := range subTokenDirs {
		aud := sub.Name()
		if strings.HasPrefix(aud, "..") {
			continue
		}
		p := filepath.Join(tokenRootDir, aud)
		c, err := utils.NewFileCache(p, tokenRefreshInterval, func(d []byte) error {
			l.data.Store(aud, string(d))
			return nil
		})
		if err != nil {
			return nil, err
		}
		l.fc = append(l.fc, c)
	}

	if _, ok := l.data.Load(audiencelessTokenName); !ok {
		return nil, fmt.Errorf("there is no UNSCOPED token found")
	}

	return l, nil
}

func (l *Local) Start(ctx context.Context) {
	for _, c := range l.fc {
		c.Start(ctx)
	}
}

// Use the token with the most domain match.
func (l *Local) FindToken(target string) (string, bool) {
	tokenCand := ""
	audCand := ""
	l.data.Range(func(k, v interface{}) bool {
		aud := k.(string)
		if aud == audiencelessTokenName {
			return true
		}
		if aud == target {
			audCand = aud
			tokenCand = v.(string)
			return false
		}
		if !strings.HasSuffix(target, aud) {
			return true
		}
		if len(aud) > len(audCand) {
			audCand = aud
			tokenCand = v.(string)
		}
		return true
	})

	if audCand == "" {
		return "", false
	}
	return tokenCand, true
}

func (l *Local) AudiencelessToken() (string, bool) {
	t, ok := l.data.Load(audiencelessTokenName)
	if !ok {
		return "", false
	}
	return t.(string), true
}
