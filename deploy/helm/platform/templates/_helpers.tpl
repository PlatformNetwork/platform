{{- define "platform.name" -}}
platform
{{- end -}}

{{- define "platform.fullname" -}}
{{- default (include "platform.name" .) .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "platform.labels" -}}
app.kubernetes.io/name: {{ include "platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "platform.validatePolicy" -}}
{{- if .Values.policy.enforceProduction -}}
{{- if or (not .Values.database.urlSecret.name) (not .Values.database.urlSecret.key) -}}
{{- fail "production policy requires database.urlSecret.name and database.urlSecret.key" -}}
{{- end -}}
{{- if eq .Values.image.tag "latest" -}}
{{- fail "production policy rejects image.tag=latest" -}}
{{- end -}}
{{- if not (regexMatch "^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$" .Values.image.tag) -}}
{{- fail "production policy requires a semver image.tag" -}}
{{- end -}}
{{- if not .Values.image.digest -}}
{{- fail "production policy requires image.digest" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-fA-F]{64}$" .Values.image.digest) -}}
{{- fail "production policy requires image.digest to be sha256" -}}
{{- end -}}
{{- range .Values.kubernetesTargets.targets -}}
{{- if and (hasKey . "verify_tls") (not .verify_tls) -}}
{{- fail (printf "production policy requires verify_tls=true for Kubernetes target %s" .id) -}}
{{- end -}}
{{- end -}}
{{- if .Values.networkPolicy.egress.allowAll -}}
{{- fail "production policy requires networkPolicy.egress.allowAll=false" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "platform.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- define "platform.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "platform.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
privileged: false
{{- end -}}
