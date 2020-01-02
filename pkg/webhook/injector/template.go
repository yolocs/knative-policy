package injector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mattbaird/jsonpatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/apis/duck"
	"knative.dev/pkg/ptr"
)

const loggingCfg = `{
	"level": "debug",
	"development": false,
	"outputPaths": ["stdout"],
	"errorOutputPaths": ["stderr"],
	"encoding": "json",
	"encoderConfig": {
		"timeKey": "ts",
		"levelKey": "level",
		"nameKey": "logger",
		"callerKey": "caller",
		"messageKey": "msg",
		"stacktraceKey": "stacktrace",
		"lineEnding": "",
		"levelEncoder": "",
		"timeEncoder": "iso8601",
		"durationEncoder": "",
		"callerEncoder": ""
	}
}`

const (
	InjectionAnnotation = "proxy.knative.dev/inject"
	SettingsAnnotation  = "proxy.knative.dev/settings"
)

const (
	DefaultTokensRoot        = "/var/run/secrets/tokens"
	DefaultUnscopedTokenName = "token-unscoped"
	DefaultJwksConfigMapName = "jwks"
)

type Config struct {
	ProxyImage        string
	ProxyInitImage    string
	ProxyInboundPort  int
	ProxyOutboundPort int
}

type ProxySettings struct {
	Audiences       []string `json:"audiences,omitempty"`
	TokenExpiration int      `json:"tokenExpiration,omitempty"`
	Jwks            string   `json:"jwks,omitempty"`
	Policy          string   `json:"policy,omitempty"`
	ServicePort     int32    `json:"servicePort,omitempty"`
	ConfigInbound   bool     `json:"configInbound,omitempty"`
	ReplyIdentity   bool     `json:"replyIdentity.omitempty"`
	PayloadPolicy   bool     `json:"payloadPolicy,omitempty"`
}

func parseProxySettings(podMeta metav1.ObjectMeta) (*ProxySettings, error) {
	ps := &ProxySettings{ConfigInbound: true}

	if s, ok := podMeta.Annotations[SettingsAnnotation]; ok {
		if err := json.Unmarshal([]byte(s), ps); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

func fillDefaults(settings *ProxySettings, podSpec *corev1.PodSpec) {
	settings.Audiences = append(settings.Audiences, "UNSCOPED")
	if settings.Jwks == "" {
		// assume a default jwks config map
		settings.Jwks = "jwks"
	}
	if settings.TokenExpiration == 0 {
		settings.TokenExpiration = 7200
	}
	if settings.ServicePort == 0 {
		for _, c := range podSpec.Containers {
			if c.Name == "user-container" {
				if len(c.Ports) == 1 {
					settings.ServicePort = c.Ports[0].ContainerPort
				} else {
					for _, p := range c.Ports {
						if p.Name == "http" {
							settings.ServicePort = p.ContainerPort
							break
						}
					}
				}
				break
			}
		}
		// Bad assumption
		if settings.ServicePort == 0 {
			settings.ServicePort = 80
		}
	}
}

func removeContainer(containers []corev1.Container, toRemove string, path string) (patches duck.JSONPatch) {
	for i := len(containers) - 1; i >= 0; i-- {
		if containers[i].Name == toRemove {
			patches = append(patches, jsonpatch.JsonPatchOperation{
				Operation: "remove",
				Path:      fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patches
}

func removeVolumes(volumes []corev1.Volume, path string) (patches duck.JSONPatch) {
	for i := len(volumes) - 1; i >= 0; i-- {
		if strings.HasPrefix(volumes[i].Name, "knp-") {
			patches = append(patches, jsonpatch.JsonPatchOperation{
				Operation: "remove",
				Path:      fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patches
}

func addContainer(target []corev1.Container, toAdd corev1.Container, basePath string) (patches duck.JSONPatch) {
	var value interface{}
	value = toAdd
	path := basePath
	if len(target) == 0 {
		value = []corev1.Container{toAdd}
	} else {
		path += "/-"
	}
	patches = append(patches, jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      path,
		Value:     value,
	})
	return patches
}

func addVolumes(target, toAdd []corev1.Volume, basePath string) (patches duck.JSONPatch) {
	first := len(target) == 0
	var value interface{}
	for _, add := range toAdd {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path += "/-"
		}
		patches = append(patches, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      path,
			Value:     value,
		})
	}
	return patches
}

func addSecurityContext(target *corev1.PodSecurityContext, basePath, action string) (patch duck.JSONPatch) {
	patch = append(patch, jsonpatch.JsonPatchOperation{
		Operation: action,
		Path:      basePath,
		Value:     target,
	})
	return patch
}

func initContainer(cfg *Config, settings *ProxySettings) corev1.Container {
	return corev1.Container{
		Name:  "kn-proxy-init",
		Image: cfg.ProxyInitImage,
		Env: []corev1.EnvVar{
			{
				Name:  "PROXY_INBOUND_PORT",
				Value: strconv.Itoa(cfg.ProxyInboundPort),
			},
			{
				Name:  "PROXY_OUTBOUND_PORT",
				Value: strconv.Itoa(cfg.ProxyOutboundPort),
			},
			{
				Name:  "SERVICE_PORT",
				Value: strconv.Itoa(int(settings.ServicePort)),
			},
			{
				Name:  "PROXY_OWNER",
				Value: "1666",
			},
		},
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		},
	}
}

func proxyContainer(cfg *Config, settings *ProxySettings, vols []corev1.Volume) corev1.Container {
	hasPolicyMount := false
	var vms []corev1.VolumeMount
	for _, v := range vols {
		path := ""
		switch v.Name {
		case "knp-tokens":
			path = "/var/run/knative/tokens"
		case "knp-jwks":
			path = "/var/run/knative/authn"
		case "knp-policy":
			path = "/var/run/knative/authz"
			hasPolicyMount = true
		}
		if path != "" {
			vms = append(vms, corev1.VolumeMount{
				Name:      v.Name,
				MountPath: path,
				ReadOnly:  true,
			})
		}
	}

	envs := []corev1.EnvVar{
		{
			Name: "NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		},
		{
			Name: "SERVICE_ACCOUNT",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "spec.serviceAccountName",
				},
			},
		},
		{
			Name:  "JWKS_FILE",
			Value: "/var/run/knative/authn/jwks.json",
		},
		{
			Name:  "TOKEN_ROOT",
			Value: "/var/run/knative/tokens",
		},
		{
			Name:  "ENABLE_REPLY_IDENTITY",
			Value: strconv.FormatBool(settings.ReplyIdentity),
		},
		{
			Name:  "ENABLE_PAYLOAD_POLICY",
			Value: strconv.FormatBool(settings.PayloadPolicy),
		},
		{
			Name:  "PROXY_INBOUND_PORT",
			Value: strconv.Itoa(cfg.ProxyInboundPort),
		},
		{
			Name:  "PROXY_OUTBOUND_PORT",
			Value: strconv.Itoa(cfg.ProxyOutboundPort),
		},
		{
			Name:  "SERVICE_PORT",
			Value: strconv.Itoa(int(settings.ServicePort)),
		},
		{
			Name:  "LOGGING_CONFIG",
			Value: loggingCfg,
		},
		{
			Name:  "LOGGING_LEVEL",
			Value: "",
		},
	}
	if hasPolicyMount {
		envs = append(envs, corev1.EnvVar{
			Name:  "POLICY_FILE",
			Value: "/var/run/knative/authz/policy.rego",
		})
	}

	return corev1.Container{
		Name:  "kn-proxy",
		Image: cfg.ProxyImage,
		Ports: []corev1.ContainerPort{
			{
				Name:          "http-proxy-in",
				ContainerPort: int32(cfg.ProxyInboundPort),
			},
			{
				Name:          "http-proxy-out",
				ContainerPort: int32(cfg.ProxyOutboundPort),
			},
		},
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem: ptr.Bool(true),
			RunAsUser:              ptr.Int64(1666),
		},
		VolumeMounts: vms,
		Env:          envs,
	}
}

func volumes(settings *ProxySettings) (vols []corev1.Volume) {
	var ts []corev1.VolumeProjection
	for _, aud := range settings.Audiences {
		a, f := aud, aud
		if a == "UNSCOPED" {
			a, f = "", "unscoped"
		}
		ts = append(ts, corev1.VolumeProjection{
			ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
				Audience:          a,
				ExpirationSeconds: ptr.Int64(int64(settings.TokenExpiration)),
				Path:              f,
			},
		})
	}
	// Tokens
	vols = append(vols, corev1.Volume{
		Name: "knp-tokens",
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: ts,
			},
		},
	})
	// Jwks
	vols = append(vols, corev1.Volume{
		Name: "knp-jwks",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: settings.Jwks,
				},
			},
		},
	})
	// Policy
	if settings.Policy != "" {
		vols = append(vols, corev1.Volume{
			Name: "knp-policy",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: settings.Policy,
					},
				},
			},
		})
	}
	return vols
}

func InjectionData(cfg *Config, pod *corev1.Pod) ([]byte, error) {
	settings, err := parseProxySettings(pod.ObjectMeta)
	if err != nil {
		return nil, fmt.Errorf("Injection failure due to invalid annotation: %w", err)
	}
	fillDefaults(settings, &pod.Spec)
	fmt.Printf("Proxy settings: %v\n", settings)

	var patches duck.JSONPatch

	patches = append(patches, removeContainer(pod.Spec.InitContainers, "kn-proxy-init", "/spec/initContainers")...)
	patches = append(patches, removeContainer(pod.Spec.Containers, "kn-proxy", "/spec/containers")...)
	patches = append(patches, removeVolumes(pod.Spec.Volumes, "/spec/volumes")...)

	patches = append(patches, addContainer(pod.Spec.InitContainers, initContainer(cfg, settings), "/spec/initContainers")...)

	vols := volumes(settings)
	patches = append(patches, addVolumes(pod.Spec.Volumes, vols, "/spec/volumes")...)
	patches = append(patches, addContainer(pod.Spec.Containers, proxyContainer(cfg, settings, vols), "/spec/containers")...)

	psc := pod.Spec.SecurityContext.DeepCopy()
	pscAction := ""
	if psc == nil {
		psc = &corev1.PodSecurityContext{
			FSGroup: ptr.Int64(1667),
		}
		pscAction = "add"
	} else {
		if psc.FSGroup == nil {
			psc.FSGroup = ptr.Int64(1667)
		}
		pscAction = "replace"
	}
	patches = append(patches, addSecurityContext(psc, "/spec/securityContext", pscAction)...)

	fmt.Printf("Patch generated: %v", patches)
	// Set envs
	// Set volume mounts
	// inbound iptables should skip localhost traffic
	return json.Marshal(patches)
}
