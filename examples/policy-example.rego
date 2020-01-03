package knative.dev

default allow = false

allow {
  startswith(input.source.identity, "system:serviceaccount:secexp1:user2")
  some i
  ce := input.request.header["Ce-Type"][i]
  startswith(ce, "echo")
}

allow {
  startswith(input.source.identity, "system:serviceaccount:secexp1:user2")
  some i
  ce := input.request.header["Ce-Eventtype"][i]
  startswith(ce, "echo")
}
