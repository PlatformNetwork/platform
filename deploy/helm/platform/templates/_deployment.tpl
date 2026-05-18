{{- define "platform.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "platform.fullname" .root }}-{{ .name }}
  labels:
    {{- include "platform.labels" .root | nindent 4 }}
    platform.component: {{ .name | quote }}
spec:
  replicas: {{ .replicas }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ include "platform.name" .root }}
      app.kubernetes.io/instance: {{ .root.Release.Name }}
      platform.component: {{ .name | quote }}
  template:
    metadata:
      labels:
        {{- include "platform.labels" .root | nindent 8 }}
        platform.component: {{ .name | quote }}
    spec:
      serviceAccountName: {{ .root.Values.kubernetes.serviceAccount }}
      automountServiceAccountToken: {{ .automountToken }}
      {{- with .root.Values.image.pullSecrets }}
      imagePullSecrets:
        {{- range . }}
        - name: {{ . }}
        {{- end }}
      {{- end }}
      securityContext:
        {{- include "platform.podSecurityContext" .root | nindent 8 }}
      containers:
        - name: {{ .name }}
          image: {{ include "platform.image" .root | quote }}
          imagePullPolicy: {{ .root.Values.image.pullPolicy }}
          command: {{ toJson .command }}
          ports:
            - name: http
              containerPort: {{ .port }}
          env:
            - name: PLATFORM_DATABASE__URL
              valueFrom:
                secretKeyRef:
                  name: {{ .root.Values.database.urlSecret.name }}
                  key: {{ .root.Values.database.urlSecret.key }}
          volumeMounts:
            - name: config
              mountPath: /app/config/master.kubernetes.yaml
              subPath: master.yaml
              readOnly: true
            - name: data
              mountPath: /var/lib/platform
            - name: secrets
              mountPath: /var/lib/platform/secrets
              readOnly: true
          readinessProbe:
            httpGet:
              path: /health
              port: http
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: http
            periodSeconds: 30
          resources:
            {{- toYaml .resources | nindent 12 }}
          securityContext:
            {{- include "platform.containerSecurityContext" .root | nindent 12 }}
      volumes:
        - name: config
          configMap:
            name: {{ include "platform.fullname" .root }}-config
        - name: data
          {{- if .root.Values.persistence.enabled }}
          persistentVolumeClaim:
            claimName: {{ include "platform.fullname" .root }}-data
          {{- else }}
          emptyDir: {}
          {{- end }}
        - name: secrets
          secret:
            secretName: {{ .root.Values.security.existingSecret }}
{{- end -}}
