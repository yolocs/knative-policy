package injector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	admissionlisters "k8s.io/client-go/listers/admissionregistration/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/kmp"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/ptr"
	"knative.dev/pkg/system"
	"knative.dev/pkg/webhook"
	certresources "knative.dev/pkg/webhook/certificates/resources"
)

type reconciler struct {
	name string
	path string

	client       kubernetes.Interface
	mwhlister    admissionlisters.MutatingWebhookConfigurationLister
	secretlister corelisters.SecretLister

	withContext func(context.Context) context.Context

	namespaceSelector *metav1.LabelSelector
	secretName        string

	cfg *Config
}

var _ controller.Reconciler = (*reconciler)(nil)
var _ webhook.AdmissionController = (*reconciler)(nil)

func (ac *reconciler) Reconcile(ctx context.Context, key string) error {
	logger := logging.FromContext(ctx)

	// Look up the webhook secret, and fetch the CA cert bundle.
	secret, err := ac.secretlister.Secrets(system.Namespace()).Get(ac.secretName)
	if err != nil {
		logger.Errorf("Error fetching secret: %v", err)
		return err
	}
	caCert, ok := secret.Data[certresources.CACert]
	if !ok {
		return fmt.Errorf("secret %q is missing %q key", ac.secretName, certresources.CACert)
	}

	// Reconcile the webhook configuration.
	return ac.reconcileMutatingWebhook(ctx, caCert)
}

func (ac *reconciler) Path() string {
	return ac.path
}

func (ac *reconciler) Admit(ctx context.Context, request *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	if ac.withContext != nil {
		ctx = ac.withContext(ctx)
	}

	logger := logging.FromContext(ctx)
	switch request.Operation {
	case admissionv1beta1.Create:
	default:
		logger.Infof("Unhandled webhook operation, letting it through %v", request.Operation)
		return &admissionv1beta1.AdmissionResponse{Allowed: true}
	}

	patchBytes, err := ac.mutate(ctx, request)
	if err != nil {
		return webhook.MakeErrorStatus("mutation failed: %v", err)
	}
	logger.Infof("Kind: %q PatchBytes: %v", request.Kind, string(patchBytes))

	if patchBytes == nil {
		return &admissionv1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	return &admissionv1beta1.AdmissionResponse{
		Patch:   patchBytes,
		Allowed: true,
		PatchType: func() *admissionv1beta1.PatchType {
			pt := admissionv1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func (ac *reconciler) mutate(ctx context.Context, request *admissionv1beta1.AdmissionRequest) ([]byte, error) {
	logger := logging.FromContext(ctx)

	var pod corev1.Pod
	if err := json.Unmarshal(request.Object.Raw, &pod); err != nil {
		return nil, fmt.Errorf("couldn't not unmarshal raw object: %w %s", err, string(request.Object.Raw))
	}

	podName := potentialPodName(&pod.ObjectMeta)
	if pod.ObjectMeta.Namespace == "" {
		pod.ObjectMeta.Namespace = request.Namespace
	}

	logger.Infof("AdmissionReview for Kind=%v Namespace=%v Name=%v (%v) UID=%v Rfc6902PatchOperation=%v UserInfo=%v",
		request.Kind, request.Namespace, request.Name, podName, request.UID, request.Operation, request.UserInfo)
	logger.Debugf("Object: %v", string(request.Object.Raw))
	logger.Debugf("OldObject: %v", string(request.OldObject.Raw))

	if !injectRequired([]string{}, &pod.Spec, &pod.ObjectMeta) {
		logger.Infof("Skipping %s/%s due to policy check", pod.ObjectMeta.Namespace, podName)
		return nil, nil
	}

	// Dry run
	// InjectionData(ac.cfg, &pod)

	// return nil, nil
	return InjectionData(ac.cfg, &pod)
}

func (ac *reconciler) reconcileMutatingWebhook(ctx context.Context, caCert []byte) error {
	logger := logging.FromContext(ctx)

	rules := []admissionregistrationv1beta1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1beta1.OperationType{
				admissionregistrationv1beta1.Create,
			},
			Rule: admissionregistrationv1beta1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
			},
		},
	}

	configuredWebhook, err := ac.mwhlister.Get(ac.name)
	if err != nil {
		return fmt.Errorf("error retrieving webhook: %v", err)
	}

	webhook := configuredWebhook.DeepCopy()

	// Clear out any previous (bad) OwnerReferences.
	// See: https://github.com/knative/serving/issues/5845
	webhook.OwnerReferences = nil

	for i, wh := range webhook.Webhooks {
		if wh.Name != webhook.Name {
			continue
		}
		webhook.Webhooks[i].Rules = rules
		webhook.Webhooks[i].ClientConfig.CABundle = caCert
		if webhook.Webhooks[i].ClientConfig.Service == nil {
			return fmt.Errorf("missing service reference for webhook: %s", wh.Name)
		}
		webhook.Webhooks[i].ClientConfig.Service.Path = ptr.String(ac.Path())
		webhook.Webhooks[i].NamespaceSelector = ac.namespaceSelector
	}

	if ok, err := kmp.SafeEqual(configuredWebhook, webhook); err != nil {
		return fmt.Errorf("error diffing webhooks: %v", err)
	} else if !ok {
		logger.Info("Updating webhook")
		mwhclient := ac.client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations()
		if _, err := mwhclient.Update(webhook); err != nil {
			return fmt.Errorf("failed to update webhook: %v", err)
		}
	} else {
		logger.Info("Webhook is valid")
	}
	return nil
}

func potentialPodName(metadata *metav1.ObjectMeta) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	if metadata.GenerateName != "" {
		return metadata.GenerateName + "***** (actual name not yet known)"
	}
	return ""
}

func injectRequired(ignored []string, podSpec *corev1.PodSpec, metadata *metav1.ObjectMeta) bool {
	if podSpec.HostNetwork {
		return false
	}

	for _, ns := range ignored {
		if metadata.Namespace == ns {
			return false
		}
	}

	annos := metadata.GetAnnotations()
	if annos == nil {
		annos = make(map[string]string)
	}

	var inject bool
	switch strings.ToLower(annos[InjectionAnnotation]) {
	case "y", "yes", "true", "on":
		inject = true
	default:
		inject = false
	}

	return inject
}
