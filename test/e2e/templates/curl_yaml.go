// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package templates

const (
	CurlYAMLTemplate = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    name: curl
spec:
  selector:
    matchLabels:
      app: curl
  replicas: {{.Replicas}}
  template:
    metadata:
      labels:
        app: curl
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - curl
            topologyKey: "kubernetes.io/hostname"
      containers:
      - name: curl
        image: byrnedo/alpine-curl
        command:
          - "sh"
          - "-c"
          - >
            while true; do
              sleep 3600;
            done

`
)
