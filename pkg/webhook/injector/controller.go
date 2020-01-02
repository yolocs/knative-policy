package injector

import (
	"context"

	// Injection stuff
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	mwhinformer "knative.dev/pkg/client/injection/kube/informers/admissionregistration/v1beta1/mutatingwebhookconfiguration"
	secretinformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"
	"knative.dev/pkg/webhook"
)

// NewAdmissionController constructs a reconciler
func NewAdmissionController(
	ctx context.Context,
	name, path string,
	wc func(context.Context) context.Context,
	cfg *Config,
) *controller.Impl {

	client := kubeclient.Get(ctx)
	mwhInformer := mwhinformer.Get(ctx)
	secretInformer := secretinformer.Get(ctx)
	options := webhook.GetOptions(ctx)

	wh := &reconciler{
		name: name,
		path: path,

		withContext: wc,
		secretName:  options.SecretName,

		client:       client,
		mwhlister:    mwhInformer.Lister(),
		secretlister: secretInformer.Lister(),

		cfg:               cfg,
		namespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"knative-injection": "enabled"}},
	}
	c := controller.NewImpl(wh, logging.FromContext(ctx), name)

	// It doesn't matter what we enqueue because we will always Reconcile
	// the named MWH resource.
	handler := controller.HandleAll(c.EnqueueSentinel(types.NamespacedName{}))

	// Reconcile when the named MutatingWebhookConfiguration changes.
	mwhInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: controller.FilterWithName(name),
		Handler:    handler,
	})

	// Reconcile when the cert bundle changes.
	secretInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: controller.FilterWithNameAndNamespace(system.Namespace(), wh.secretName),
		Handler:    handler,
	})

	return c
}
