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
Name to use for objects whose name must be unique across the whole cluster: currently the
ClusterRole and ClusterRoleBindings, and the RoleBinding created in kube-system. Use this helper
for any object with that requirement, so that clusterScopedNameSuffix can be used to install
several instances of the chart (in different Namespaces) without them stealing each other's
cluster-scoped objects.
*/}}
{{- define "flow-aggregator.clusterScopedName" -}}
{{- $suffix := "" }}
{{- if not (kindIs "invalid" .Values.clusterScopedNameSuffix) }}
{{- /* toString so that a suffix such as "-1", which Helm's --set coerces to an integer, is still rendered as a string. */}}
{{- $suffix = toString .Values.clusterScopedNameSuffix }}
{{- end }}
{{- printf "%s%s" (include "flow-aggregator.fullname" .) $suffix }}
{{- end }}
