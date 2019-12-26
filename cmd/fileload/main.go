package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/yolocs/knative-policy/pkg/authz"
)

var (
	filePath = flag.String("filepath", "", "file to cache")
)

func main() {
	flag.Parse()

	// j, err := proxy.NewJwks(*filePath)
	// if err != nil {
	// 	log.Error(err.Error())
	// 	os.Exit(1)
	// }

	// rawToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsic3lzdGVtOnNlcnZpY2VhY2NvdW50Om5zMTpldmVudGluZy1icm9rZXItaW5ncmVzcyJdLCJleHAiOjE1NzY4ODM0MjcsImlhdCI6MTU3Njc5NzAyNywiaXNzIjoiaHR0cHM6Ly9jb250YWluZXIuZ29vZ2xlYXBpcy5jb20vdjEvcHJvamVjdHMvY3Nob3UtcGxheWdyb3VuZC9sb2NhdGlvbnMvdXMtd2VzdDEtYy9jbHVzdGVycy9uby1pc3RpbyIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoibnMxIiwicG9kIjp7Im5hbWUiOiJjdXJsIiwidWlkIjoiYmUzMWFlNTEtMjJiNC0xMWVhLWE4YWQtNDIwMTBhOGEwMTZmIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJjdXJsZXIiLCJ1aWQiOiI2NzMyZDE2Zi0yMjkyLTExZWEtYThhZC00MjAxMGE4YTAxNmYifX0sIm5iZiI6MTU3Njc5NzAyNywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Om5zMTpjdXJsZXIifQ.q3Z0blIQIfdhnJFToM6eBD7N7mL61cGaWlfR9uRcwDKB8pVfifG06iXLc4re9PjNIwFQT9hfbTXYqBjpdIkCFgZSZ-m6UMrdp-11ZHsZ7edl2c-23L9UIGbatMjontZTyYeD3pa_X7Ti7aviKdjMTDc9rFqb-yDTI22K0WZcjXylH6UhhGdn9T_dSQ3mUwiEc7K1tSHCJ9dQo8H6mW6dtL0juS9-zIIyeZJhbM9ofIzt1zdexeu9iHrwltO0pujB2rwhmgst7a_i0xN2TxwBMCVmc6S9Muowqx6QaSDB6y6KIMwt2JjVA2qmOKq-ovsTKE_vUsHiHrPW4vuDm0WjwQ"

	// c, err := j.GetClaims(rawToken)
	// if err != nil {
	// 	log.Error(err.Error())
	// 	os.Exit(1)
	// }
	// fmt.Printf("Claims: %v", c)

	p, err := authz.NewPolicies(*filePath)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	fmt.Printf("Is allowed? %v", p.IsAllowed("system:serviceaccount:default:user2", nil, nil))
}
