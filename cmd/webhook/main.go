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
			ProxyImage:        "gcr.io/cshou-playground/proxy-3e029f88b6d98bb38d5aadffc575c420@sha256:2c4c4c35649a3ce3ebd51396b1d36bfbd26b57db0540c56d727cc22caddb1d17",
			ProxyInitImage:    "gcr.io/cshou-playground/proxy-init-8d73b8e06c8aee6d6697e33267e0213d@sha256:32635f13d26a0a2b652cbe09d7b40bb99a0b36c10d116152840892c9435ee172",
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
