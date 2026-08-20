{{- define "flowAggregatorImageTag" -}}
{{- if .Values.image.tag }}
{{- .Values.image.tag -}}
{{- else if eq .Chart.AppVersion "latest" }}
{{- print "latest" -}}
{{- else }}
{{- print "v" .Chart.AppVersion -}}
{{- end }}
{{- end -}}

{{- define "flowAggregatorImage" -}}
{{- print .Values.image.repository ":" (include "flowAggregatorImageTag" .) -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "flow-aggregator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Name to use for RBAC objects which are not created in the release Namespace: the ClusterRole and
ClusterRoleBindings, and the RoleBinding created in kube-system. Because these names must be unique
across the whole cluster, clusterScopedRBACNameSuffix can be used to install several instances of
the chart (in different Namespaces) without them stealing each other's RBAC bindings.
*/}}
{{- define "flow-aggregator.clusterScopedRBACName" -}}
{{- $suffix := "" }}
{{- if .Values.clusterScopedRBACNameSuffix }}
{{- /* printf %v so that a suffix such as "-1", which Helm's --set coerces to an integer, is still rendered as a string. */}}
{{- $suffix = printf "%v" .Values.clusterScopedRBACNameSuffix }}
{{- end }}
{{- printf "%s%s" (include "flow-aggregator.fullname" .) $suffix | trunc 63 | trimSuffix "-" }}
{{- end }}
