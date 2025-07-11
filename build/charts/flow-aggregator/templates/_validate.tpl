{{- define "validateReplicas" -}}
  {{- if eq .Values.mode "Aggregate"}}
    {{- if gt (int .Values.replicas) 1 }}
      {{- fail "Flow-aggregator can only have at most 1 replica in 'Aggregate' mode." }}
    {{- end }}
  {{- end }}
{{- end }}

{{- define "validateAutoscaling" -}}
  {{- with .Values.autoscaling }}
    {{- if and (ne $.Values.mode "Proxy") .enable }}
      {{- fail "Autoscaling can only be used in 'Proxy' mode." }}
    {{- end }}
    {{- if gt .minReplicas .maxReplicas }}
      {{- fail "autoscaling.minReplicas must be less than or equal to autoscaling.maxReplicas." }}
    {{- end }}
  {{- end }}
{{- end }}
