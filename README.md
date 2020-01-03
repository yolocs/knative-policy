# knative-policy
My Knative Policy Experiments

## Components

### Proxy

Proxy internally has two HTTP server: one handles inbound requests and one handles outbound requests.

#### Outbound

The outbound server is responsible to attach service account token as a special header to the outgoing requests. It uses [projected service account token volume](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection) to mount token(s) as a volume.

One problem with this is that we need to know the audience(s) when we project the volume. Currently the proxy uses a domain match logic to select the token to use. If the match fails, no token will be attached to the outgoing request (to prevent token leakage).

#### Inbound

The inbound server validates the incoming requests' service account token. It requires that the proxy to know the JWKs from the JWT issuer. Currently this step is done manually by grabing the JWKs and save it as a ConfigMap in the cluster.

Once the identity is verified, the inbound server checks the policy against the request. The policy is also saved in a ConfigMap as a `rego` file. The inbound server uses the OPA rego lib to check if the request should be allowed. If so, the request will be forwarded to the application container.

On response, the inbound server can also be configured to return a service account token. This is useful in cases where the receiver wants the requester to delegate some work, e.g. an event receiver replies an event to a channel to send to another service.

### Proxy Init

The proxy init simplies writes `iptables` so that all requests will be intercepted by the proxy. Notice it doesn't work with HTTPS.

### Webhook

The webhook listens on pod creation and injects proxy container. This only works well when there is no service mesh involved.