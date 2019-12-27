package knative.dev

default allow = false

allow {
  startswith(input.source.identity, "system:serviceaccount:ptst1:user")
  input.request.header["Ce-Type"][_] == "echo"
  input.request.body["trait"] == "test"
}