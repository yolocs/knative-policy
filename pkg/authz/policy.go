package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/yolocs/knative-policy/pkg/utils"
)

var policyRefreshInterval time.Duration = 15 * time.Second

type Policies struct {
	// Use a whitelist for now
	data map[string]bool
	mux  *sync.RWMutex

	fc *utils.FileCache
}

func NewPolicies(filePath string) (*Policies, error) {
	p := &Policies{data: make(map[string]bool), mux: &sync.RWMutex{}}
	fc, err := utils.NewFileCache(filePath, policyRefreshInterval, p.unmarshal)
	if err != nil {
		return nil, err
	}
	p.fc = fc
	return p, nil
}

func (p *Policies) Start(ctx context.Context) {
	p.fc.Start(ctx)
}

func (p *Policies) IsAllowed(subject string, _ http.Header, _ []byte) bool {
	_, ok := p.data[subject]
	return ok
}

func (p *Policies) unmarshal(data []byte) error {
	d := make(map[string]bool)
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	p.mux.Lock()
	defer p.mux.Unlock()

	p.data = d
	return nil
}
