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

{{- define "antreaAgentImageTag" -}}
{{- if .Values.agentImage.tag }}
{{- .Values.agentImage.tag -}}
{{- else if eq .Chart.AppVersion "latest" }}
{{- print "latest" -}}
{{- else }}
{{- print "v" .Chart.AppVersion -}}
{{- end }}
{{- end -}}

{{- define "antreaControllerImageTag" -}}
{{- if .Values.controllerImage.tag }}
{{- .Values.controllerImage.tag -}}
{{- else if eq .Chart.AppVersion "latest" }}
{{- print "latest" -}}
{{- else }}
{{- print "v" .Chart.AppVersion -}}
{{- end }}
{{- end -}}

{{- define "antreaControllerImage" -}}
{{- if .Values.image }}
{{- print .Values.image.repository ":" (include "antreaImageTag" .) -}}
{{- else }}
{{- print .Values.controllerImage.repository ":" (include "antreaControllerImageTag" .) -}}
{{- end }}
{{- end -}}

{{- define "antreaAgentImage" -}}
{{- if .Values.image }}
{{- print .Values.image.repository ":" (include "antreaImageTag" .) -}}
{{- else }}
{{- print .Values.agentImage.repository ":" (include "antreaAgentImageTag" .) -}}
{{- end }}
{{- end -}}

{{- define "antreaAgentImagePullPolicy" -}}
{{- if .Values.image }}
{{- print .Values.image.pullPolicy -}}
{{- else }}
{{- print .Values.agentImage.pullPolicy -}}
{{- end }}
{{- end -}}

{{- define "antreaControllerImagePullPolicy" -}}
{{- if .Values.image }}
{{- print .Values.image.pullPolicy -}}
{{- else }}
{{- print .Values.controllerImage.pullPolicy -}}
{{- end }}
{{- end -}}

{{- define "validateValues" -}}
{{- if (.Values.whereabouts).enable -}}
{{- fail "Whereabouts is no longer included with Antrea and whereabouts.enable must not be set" -}}
{{- end -}}
{{- end -}}
