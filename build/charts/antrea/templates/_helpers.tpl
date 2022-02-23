{{- define "featureGate" -}}
{{- $name := .name }}
{{- $default := .default }}
{{- if hasKey .featureGates $name }}
    {{ $name }}: {{ get .featureGates $name }}
{{- else }}
  {{ printf "#  %s" $name }}: {{ $default }}
{{- end }}
{{- end -}}
