## What does this do?

Using the functionalities provided in this repo to enforce runtime policy of several Knative Eventing components.

## Setup

### Patch Eventing

It requires some change to the deployment template used in Eventing. The change only exists in my forked Eventing [branch](https://github.com/yolocs/eventing/tree/impersonation). The branch also adds the capability for the broker to impersonate service accounts.

To install, **check out my branch** and:

```bash
cd ${GOPATH}/src/knative.dev/eventing && ko apply -f ./config
```

### Prepare Policy Components

Fork this repo, and:

```bash
cd ${GOPATH}/src/github.com/yolocs/knative-policy && ko apply -f ./config/webhook.yaml
```

This will create a namespace `knative-policy` and install a webhook that does the auto proxy injection.

### Prepare a Namespace

Find your cluster JWK. For GKE, you can find the JWK at `https://container.googleapis.com/v1/projects/[YOUR PROJECT]/locations/[CLUSTER LOCATION]/clusters/[CLUSTER NAME]/jwks`

```bash
cd ${GOPATH}/src/github.com/yolocs/knative-policy/examples/eventing-demo

CLUSTER=https://container.googleapis.com/v1/projects/[YOUR PROJECT]/locations/[CLUSTER LOCATION]/clusters/[CLUSTER NAME]

wget "${CLUSTER}/jwks" && mv jwks jwks.json && sed -i "s@keys@${CLUSTER}@g" jwks.json
```

Use the setup script.

```bash
export KNP_DEMO_NS=my-ns

cd ${GOPATH}/src/github.com/yolocs/knative-policy/examples/eventing-demo && ./setup
```

The comments in the script explain what it does.

## Test

Send events from `curl` pod:

```bash
kubectl exec curl-proxy -it -c curl-proxy -- /bin/sh
/ # curl -v "http://default-broker.my-ns.svc.cluster.local" -X POST -H "Ce-Id: say-echo" -H "Ce-Specversion: 1.0" -H "Ce-Type: echo" -H "Ce-Source: not-sendoff" -H "Content-Type: application/json" -d '{"number":0}'
...
* Connected to default-broker.my-ns.svc.cluster.local (10.0.57.114) port 80 (#0)
> POST / HTTP/1.1
> Host: default-broker.my-ns.svc.cluster.local
> User-Agent: curl/7.64.0
> Accept: */*
> Ce-Id: say-echo
> Ce-Specversion: 1.0
> Ce-Type: echo
> Ce-Source: not-sendoff
> Content-Type: application/json
> Content-Length: 12
>
* upload completely sent off: 12 out of 12 bytes
< HTTP/1.1 403 Forbidden
< Content-Length: 0
< Date: Fri, 03 Jan 2020 18:26:02 GMT
<
```

Because the broker initial policy doesn't accept `curler` as the requester, we got `403`. We can now change the broker ingress policy.

```bash
kubectl edit -n my-ns cm broker-in-policy
```

And update the config map and save.

```yaml
# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
  policy.rego: |-
    package knative.dev

    default allow = false

    allow {
      startswith(input.source.identity, "system:serviceaccount:my-ns:eventing-broker-filter")
    }

    # Add the following.
    allow {
      input.source.identity == "system:serviceaccount:my-ns:curler"
    }
kind: ConfigMap
metadata:
  name: broker-in-policy
  namespace: my-ns
```

And wait about 30 seconds for the policy to be propagated. Then try sending the event again from the `curl` pod.

```bash
kubectl exec curl-proxy -it -c curl-proxy -- /bin/sh
/ # curl -v "http://default-broker.my-ns.svc.cluster.local" -X POST -H "Ce-Id: say-echo" -H "Ce-Specversion: 1.0" -H "Ce-Type: echo" -H "Ce-Source: not-sendoff" -H "Content-Type: application/json" -d '{"number":0}'
...
* Connected to default-broker.my-ns.svc.cluster.local (10.0.57.114) port 80 (#0)
> POST / HTTP/1.1
> Host: default-broker.my-ns.svc.cluster.local
> User-Agent: curl/7.64.0
> Accept: */*
> Ce-Id: say-echo
> Ce-Specversion: 1.0
> Ce-Type: echo
> Ce-Source: not-sendoff
> Content-Type: application/json
> Content-Length: 12
>
* upload completely sent off: 12 out of 12 bytes
< HTTP/1.1 202 Accepted
< Content-Length: 0
< Date: Fri, 03 Jan 2020 18:39:32 GMT
<
```

Now the event is accepted `202`. But our `echo-event` service didn't really receive the event. From the broker filter log:

```
{"level":"warn","ts":1578076848.365243,"logger":"fallback","caller":"http/transport.go:594","msg":"error returned from invokeReceiver","error":"error sending cloudevent: 403 Forbidden"}
```

This is because the `echo-event` service is using the default policy we set which is denied all. To change that:

```bash
kubectl edit -n my-ns cm default-policy
```

And update the config map and save.

```yaml
# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
  policy.rego: |
    package knative.dev

    default allow = false

    # Add the following
    allow = {
      input.source.identity == "system:serviceaccount:my-ns:robot1"
    }
kind: ConfigMap
metadata:
  name: default-policy
  namespace: my-ns
```

This allows `robot1` service account to send events to the `echo-event` service. `robot1` was set up in the trigger as an annotation. That's how the broker understands which service account to impersonate.

```yaml
apiVersion: eventing.knative.dev/v1alpha1
kind: Trigger
metadata:
  annotations:
    impersonate.knative.dev: system:serviceaccount:my-ns:robot1
```

Now let's try send the event again. Now in the `echo-event` service we see log:

```
time="2020-01-03T18:49:56Z" level=info msg="Validation: valid\nContext Attributes,\n  specversion: 1.0\n  type: echo\n  source: not-sendoff\n  id: say-echo\n  time: 2020-01-03T18:49:56.656678683Z\n  datacontenttype: application/json\nExtensions,\n  knativearrivaltime: 2020-01-03T18:49:56Z\n  knativehistory: default-kne-trigger-kn-channel.autosec5.svc.cluster.local\n  traceparent: 00-37582c767b478711a3ca1ecf0e91506a-68279a63df9d59fc-00\nData,\n  {\n    \"number\": 0\n  }\n"

...

time="2020-01-03T18:49:56Z" level=info msg="Validation: valid\nContext Attributes,\n  cloudEventsVersion: 0.1\n  eventType: echo-response\n  source: not-sendoff\n  eventID: say-echo\n  eventTime: 2020-01-03T18:49:56.656678683Z\n  contentType: application/json\nExtensions,\n  Knativearrivaltime: 2020-01-03T18:49:56Z\n  Knativebrokerttl: 255\n  Knativehistory: default-kne-trigger-kn-channel.autosec5.svc.cluster.local\n  Traceparent: 00-e3c362a590194d1141bd6ddbfe9382a7-ace558f226bbec46-00\nData,\n  {\n    \"number\": 0\n  }\n"
```

As we can see the first event was the event we sent. The second event was the event replied (echoed) by the service and the service also received it (it has event type = `echo-response`).

### Fanier Policy

To have *fancier* policy, let's say we want to allow the broker to only accept the events with payload `number` less than 10. Let's edit the ingress policy again.

```bash
kubectl edit -n my-ns cm broker-in-policy
```

And update the config map and save.

```yaml
# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
  policy.rego: |-
    package knative.dev

    default allow = false

    allow {
      startswith(input.source.identity, "system:serviceaccount:my-ns:eventing-broker-filter")
    }

    allow {
      input.source.identity == "system:serviceaccount:my-ns:curler"
      input.request.body.number < 10
    }
kind: ConfigMap
metadata:
  name: broker-in-policy
  namespace: my-ns
```

And send the following events.

```bash
kubectl exec curl-proxy -it -c curl-proxy -- /bin/sh
/ # curl -v "http://default-broker.my-ns.svc.cluster.local" -X POST -H "Ce-Id: say-echo" -H "Ce-Specversion: 1.0" -H "Ce-Type: echo" -H "Ce-Source: not-sendoff" -H "Content-Type: application/json" -d '{"number":20}'
...
* Connected to default-broker.my-ns.svc.cluster.local (10.0.57.114) port 80 (#0)
> POST / HTTP/1.1
> Host: default-broker.my-ns.svc.cluster.local
> User-Agent: curl/7.64.0
> Accept: */*
> Ce-Id: say-echo
> Ce-Specversion: 1.0
> Ce-Type: echo
> Ce-Source: not-sendoff
> Content-Type: application/json
> Content-Length: 12
>
* upload completely sent off: 12 out of 12 bytes
< HTTP/1.1 403 Forbidden
< Content-Length: 0
< Date: Fri, 03 Jan 2020 18:26:02 GMT
<

/ # curl -v "http://default-broker.my-ns.svc.cluster.local" -X POST -H "Ce-Id: say-echo" -H "Ce-Specversion: 1.0" -H "Ce-Type: echo" -H "Ce-Source: not-sendoff" -H "Content-Type: application/json" -d '{"number":8}'
...
* Connected to default-broker.my-ns.svc.cluster.local (10.0.57.114) port 80 (#0)
> POST / HTTP/1.1
> Host: default-broker.my-ns.svc.cluster.local
> User-Agent: curl/7.64.0
> Accept: */*
> Ce-Id: say-echo
> Ce-Specversion: 1.0
> Ce-Type: echo
> Ce-Source: not-sendoff
> Content-Type: application/json
> Content-Length: 12
>
* upload completely sent off: 12 out of 12 bytes
< HTTP/1.1 202 Accepted
< Content-Length: 0
< Date: Fri, 03 Jan 2020 19:01:32 GMT
```