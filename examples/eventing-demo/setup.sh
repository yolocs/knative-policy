#!/bin/bash

# Create a namespace
kubectl create ns ${KNP_DEMO_NS}

# Create a config map for the cluster JWK.
kubectl create cm jwks --from-file jwks.json -n ${KNP_DEMO_NS}

# Create a default policy that allows nothing.
kubectl apply -f default-policy.yaml -n ${KNP_DEMO_NS}

# Create a broker filter policy that only accepts imc-dispatcher requests.
kubectl apply -f broker-filter-policy.yaml -n ${KNP_DEMO_NS}

# Create a broker ingress policy that only accepts broker filter requests (from replied events).
cat broker-ingress-policy-template.yaml | sed "s@{{.NAMESPACE}}@${KNP_DEMO_NS}@g" | sed 's@{{.CUSTOM_POLICY}}@@g' | kubectl apply -n ${KNP_DEMO_NS} -f -

# Grant broker filter service account the permission to impersonate other service accounts.
cat impersonate-template.yaml | sed "s@{{.NAMESPACE}}@${KNP_DEMO_NS}@g" | kubectl apply -f -

# Label the namespace for policy proxy injection.
kubectl label namespace ${KNP_DEMO_NS} knative-injection=enabled

# Label the namespace for eventing.
kubectl label namespace ${KNP_DEMO_NS} knative-eventing-injection=enabled

# Create a service that echos events.
kubectl apply -n ${KNP_DEMO_NS} -f echo-event.yaml

# Create a service account and create a trigger that requires events to be pushed as the service account.
account=robot1
kubectl create -n ${KNP_DEMO_NS} sa ${account}
cat trigger-template.yaml | sed "s@{{.NAMESPACE}}@${KNP_DEMO_NS}@g" | sed "s@{{.ACCOUNT}}@${account}@g" | kubectl apply -n ${KNP_DEMO_NS} -f -

# Create a curl pod for testing purpose.
kubectl create -n ${KNP_DEMO_NS} sa curler
cat curl-template.yaml | sed "s@{{.NAMESPACE}}@${KNP_DEMO_NS}@g" | kubectl apply -n ${KNP_DEMO_NS} -f -