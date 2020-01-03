package main

import (
	"context"

	"github.com/yolocs/knative-policy/pkg/webhook/injector"
	"knative.dev/eventing/pkg/logconfig"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"
)

func NewInjectorAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	return injector.NewAdmissionController(ctx,

		// Name of the resource webhook.
		"webhook.policy.knative.dev",

		// The path on which to serve the webhook.
		"/inject",

		func(ctx context.Context) context.Context {
			return ctx
		},

		// Whether to disallow unknown fields.
		&injector.Config{
			ProxyImage:        "gcr.io/cshou-playground/proxy-3e029f88b6d98bb38d5aadffc575c420@sha256:0a9d3baaf5fb7f43550f3abd98bfd62e0cb8a7717faa527a3f09e396dc87cc2f",
			ProxyInitImage:    "gcr.io/cshou-playground/proxy-init-8d73b8e06c8aee6d6697e33267e0213d@sha256:d2ca0f8b6e49a89d9c352f1de53563bac2892199390581fbbf64364b060cd99a",
			ProxyInboundPort:  8101,
			ProxyOutboundPort: 8102,
		},
	)
}

func main() {
	// Set up a signal context with our webhook options
	ctx := webhook.WithOptions(signals.NewContext(), webhook.Options{
		ServiceName: logconfig.WebhookName(),
		Port:        8443,
		// SecretName must match the name of the Secret created in the configuration.
		SecretName: "policy-webhook-certs",
	})

	sharedmain.MainWithContext(ctx, logconfig.WebhookName(),
		certificates.NewController,
		NewInjectorAdmissionController,
	)
}
