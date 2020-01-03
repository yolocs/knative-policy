package authz

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/yolocs/knative-policy/pkg/utils"
	"go.uber.org/zap"
)

var opaPolicyRefreshInterval time.Duration = 30 * time.Second

type EvalInput struct {
	Source  Source         `json:"source,omitempty"`
	Request PartialRequest `json:"request,omitempty"`
}

type Source struct {
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	Identity string `json:"identity,omitempty"`
}

type PartialRequest struct {
	Method        string                 `json:"method,omitempty"`
	Host          string                 `json:"host,omitempty"`
	Path          string                 `json:"path,omitempty"`
	Header        http.Header            `json:"header,omitempty"`
	ContentLength int64                  `json:"contentLength,omitempty"`
	RemoteAddr    string                 `json:"remoteAddr,omitempty"`
	Body          map[string]interface{} `json:"body,omitempty"`
}

type OPAPolicy struct {
	mux         *sync.RWMutex
	cachedQuery rego.PreparedEvalQuery

	fc *utils.FileCache

	logger *zap.SugaredLogger
}

func NewOPAPolicy(logger *zap.SugaredLogger, filepath string) (*OPAPolicy, error) {
	o := &OPAPolicy{logger: logger, mux: &sync.RWMutex{}}
	fc, err := utils.NewFileCache(filepath, opaPolicyRefreshInterval, o.reloadRego)
	if err != nil {
		return nil, err
	}
	o.fc = fc
	return o, nil
}

func (o *OPAPolicy) Start(ctx context.Context) {
	o.fc.Start(ctx)
}

func (o *OPAPolicy) IsAllowed(ctx context.Context, input EvalInput) bool {
	o.mux.RLock()
	defer o.mux.RUnlock()

	o.logger.Debugf("Evaluating input: %v", input)

	rs, err := o.cachedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		o.logger.Warnw("failed to evaluate input and will fail-close", zap.Error(err))
		return false
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false
	}

	o.logger.Debugf("Eval result: %v", rs[0])

	// Super hacky
	return strings.Contains(fmt.Sprintf("%v", rs[0]), "true")
}

func (o *OPAPolicy) reloadRego(data []byte) error {
	module := string(data)
	compiler, err := ast.CompileModules(map[string]string{
		"knative.dev": module,
	})
	if err != nil {
		return fmt.Errorf("failed to compile rego module: %w", err)
	}

	r := rego.New(
		rego.Query("data.knative.dev.allow"),
		rego.Compiler(compiler),
		rego.Dump(os.Stdout),
	)

	pq, err := r.PrepareForEval(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to prepare for eval: %w", err)
	}

	o.mux.Lock()
	defer o.mux.Unlock()

	o.cachedQuery = pq
	return nil
}
