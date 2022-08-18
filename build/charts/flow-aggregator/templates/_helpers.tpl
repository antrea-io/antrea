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
