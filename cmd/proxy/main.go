package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"

	"github.com/kelseyhightower/envconfig"
	"github.com/yolocs/knative-policy/pkg/authn"
	"github.com/yolocs/knative-policy/pkg/authz"
	"github.com/yolocs/knative-policy/pkg/proxy"
	"github.com/yolocs/knative-policy/pkg/token"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
	pkglogging "knative.dev/pkg/logging"
	"knative.dev/pkg/logging/logkey"
	pkgnet "knative.dev/pkg/network"
	"knative.dev/pkg/signals"
)

type config struct {
	ProxyInboundPort  int    `split_words:"true" required:"true"`
	ProxyOutboundPort int    `split_words:"true" required:"true"`
	ServicePort       int    `split_words:"true" required:"true"`
	Namespace         string `split_words:"true" required:"true"`
	ServiceAccount    string `split_words:"true" required:"true"`

	LoggingConfig string `split_words:"true" required:"true"`
	LoggingLevel  string `split_words:"true" required:"true"`

	JwksFile   string `split_words:"true" required:"true"`
	PolicyFile string `split_words:"true" required:"true"`
	TokenRoot  string `split_words:"true" required:"true"`

	EnablePayloadPolicy bool `split_words:"true"`
	EnableReplyIdentity bool `split_words:"true"`
}

var logger *zap.SugaredLogger

func main() {
	// Parse the environment.
	var env config
	if err := envconfig.Process("", &env); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logger, _ = pkglogging.NewLogger(env.LoggingConfig, env.LoggingLevel)
	logger = logger.Named("kn-proxy")
	defer flush(logger)

	logger = logger.With(
		zap.String(logkey.Key, types.NamespacedName{
			Namespace: env.Namespace,
			Name:      env.ServiceAccount,
		}.String()))
	ctx, cancel := context.WithCancel(pkglogging.WithLogger(context.Background(), logger))

	jwks, err := authn.NewJwks(env.JwksFile)
	if err != nil {
		logger.Fatalf("failed to load JWKs: %v", err)
	}
	opapolicy, err := authz.NewOPAPolicy(logger, env.PolicyFile)
	if err != nil {
		logger.Fatalf("failed to load OPA policy: %v", err)
	}
	tokens, err := token.NewLocal(env.TokenRoot)
	if err != nil {
		logger.Fatalf("failed to load tokens: %v", err)
	}
	// Start file refreshes
	jwks.Start(ctx)
	opapolicy.Start(ctx)
	tokens.Start(ctx)

	inbound := &proxy.Inbound{
		Jwks:                 jwks,
		Policy:               opapolicy,
		Tokens:               tokens,
		ApplyPolicyOnPayload: env.EnablePayloadPolicy,
		ReplyWithIdentity:    env.EnableReplyIdentity,
		Logger:               logger,
	}

	outbound := &proxy.Outbound{
		Tokens:    tokens,
		Transport: pkgnet.AutoTransport,
		Logger:    logger,
	}

	servers := map[string]*http.Server{
		"inbound":  buildInboundServer(logger, env, inbound),
		"outbound": pkgnet.NewServer(":"+strconv.Itoa(env.ProxyOutboundPort), outbound),
	}

	errCh := make(chan error, len(servers))
	for name, server := range servers {
		go func(name string, s *http.Server) {
			logger.Infof("Starting server %q...", name)
			if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("%s server failed: %w", name, err)
			}
		}(name, server)
	}

	// Blocks until we actually receive a TERM signal or one of the servers
	// exit unexpectedly. We fold both signals together because we only want
	// to act on the first of those to reach here.
	select {
	case err := <-errCh:
		logger.Errorw("Failed to bring up kn-proxy, shutting down.", zap.Error(err))
		flush(logger)
		os.Exit(1)
	case <-signals.SetupSignalHandler():
		logger.Info("Received TERM signal, attempting to gracefully shutdown servers.")
		flush(logger)
		cancel()
		for serverName, srv := range servers {
			if err := srv.Shutdown(context.Background()); err != nil {
				logger.Errorw("Failed to shutdown server", zap.String("server", serverName), zap.Error(err))
			}
		}
	}
}

func buildInboundServer(logger *zap.SugaredLogger, env config, inbound *proxy.Inbound) *http.Server {
	target := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(env.ServicePort)),
	}

	httpProxy := httputil.NewSingleHostReverseProxy(target)
	httpProxy.Transport = pkgnet.AutoTransport
	httpProxy.ErrorHandler = pkgnet.ErrorHandler(logger)
	httpProxy.ModifyResponse = inbound.ModifyReponse
	httpProxy.FlushInterval = -1

	var composedHandler http.Handler = httpProxy
	composedHandler = http.HandlerFunc(inbound.Handler(composedHandler))

	return pkgnet.NewServer(":"+strconv.Itoa(env.ProxyInboundPort), composedHandler)
}

func flush(logger *zap.SugaredLogger) {
	logger.Sync()
	os.Stdout.Sync()
	os.Stderr.Sync()
}
