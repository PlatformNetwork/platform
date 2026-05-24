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
{{- if eq .Values.master.namespace .Values.validator.namespace -}}
{{- fail "master.namespace and validator.namespace must differ" -}}
{{- end -}}
{{- if .Values.policy.enforceProduction -}}
{{- if or (not .Values.database.urlSecret.name) (not .Values.database.urlSecret.key) -}}
{{- fail "production policy requires database.urlSecret.name and database.urlSecret.key" -}}
{{- end -}}
{{- if .Values.imageAutoUpdate.enabled -}}
{{- fail "production policy rejects imageAutoUpdate.enabled=true" -}}
{{- end -}}
{{- if .Values.autoUpgrade.enabled -}}
{{- if eq .Values.autoUpgrade.githubRef "main" -}}
{{- fail "autoUpgrade.githubRef must be immutable in production" -}}
{{- end -}}
{{- include "platform.validateImagePolicy" (dict "image" .Values.autoUpgrade.helmImage "name" "autoUpgrade.helmImage") -}}
{{- end -}}
{{- include "platform.validateImagePolicy" (dict "image" .Values.image "name" "image") -}}
{{- include "platform.validateImagePolicy" (dict "image" .Values.images.master "name" "images.master") -}}
{{- include "platform.validateImagePolicy" (dict "image" .Values.images.validator "name" "images.validator") -}}
{{- include "platform.validateImagePolicy" (dict "image" .Values.images.updater "name" "images.updater") -}}
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

{{- define "platform.validateImagePolicy" -}}
{{- if eq .image.tag "latest" -}}
{{- fail (printf "production policy rejects %s.tag=latest" .name) -}}
{{- end -}}
{{- if not (regexMatch "^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$" .image.tag) -}}
{{- fail (printf "production policy requires a semver %s.tag" .name) -}}
{{- end -}}
{{- if not .image.digest -}}
{{- fail (printf "production policy requires %s.digest" .name) -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-fA-F]{64}$" .image.digest) -}}
{{- fail (printf "production policy requires %s.digest to be sha256" .name) -}}
{{- end -}}
{{- end -}}

{{- define "platform.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- define "platform.imageValue" -}}
{{- $image := .image -}}
{{- if $image.digest -}}
{{ $image.repository }}:{{ $image.tag }}@{{ $image.digest }}
{{- else -}}
{{ $image.repository }}:{{ $image.tag }}
{{- end -}}
{{- end -}}

{{- define "platform.mutableImageValue" -}}
{{- $image := .image -}}
{{ $image.repository }}:{{ $image.tag }}
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

{{- define "platform.serviceAccountName" -}}
{{- if .Values.master.enabled -}}
{{ .Values.kubernetes.serviceAccount }}
{{- else -}}
{{ include "platform.fullname" . }}
{{- end -}}
{{- end -}}

{{- define "platform.validatorDeploymentName" -}}
{{- .Values.validator.deploymentNameOverride | default (printf "%s-validator" (include "platform.fullname" .)) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
