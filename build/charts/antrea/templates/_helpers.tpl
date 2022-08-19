{{- define "featureGate" -}}
{{- $name := .name }}
{{- $default := .default }}
{{- if hasKey .featureGates $name }}
    {{ $name }}: {{ get .featureGates $name }}
{{- else }}
  {{ printf "#  %s" $name }}: {{ $default }}
{{- end }}
{{- end -}}

{{- define "antreaImageTag" -}}
{{- if .Values.image.tag }}
{{- .Values.image.tag -}}
{{- else if eq .Chart.AppVersion "latest" }}
{{- print "latest" -}}
{{- else }}
{{- print "v" .Chart.AppVersion -}}
{{- end }}
{{- end -}}

{{- define "antreaImage" -}}
{{- print .Values.image.repository ":" (include "antreaImageTag" .) -}}
{{- end -}}
