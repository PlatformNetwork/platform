#!/usr/bin/env bash
set -euo pipefail
umask 077

APP="platform-master"
NAMESPACE="${PLATFORM_NAMESPACE:-platform-master}"
IMAGE="${PLATFORM_MASTER_IMAGE:-ghcr.io/platformnetwork/platform-master:latest}"
AUTO_UPGRADE_SCHEDULE="${PLATFORM_AUTO_UPGRADE_SCHEDULE:-*/5 * * * *}"
AUTO_UPGRADE_HELM_IMAGE="${PLATFORM_AUTO_UPGRADE_HELM_IMAGE:-alpine/helm:3.15.4}"
AUTO_UPGRADE_REPO="${PLATFORM_AUTO_UPGRADE_REPO:-PlatformNetwork/platform}"
AUTO_UPGRADE_REF="${PLATFORM_AUTO_UPGRADE_REF:-main}"
AUTO_UPGRADE_CHART_PATH="${PLATFORM_AUTO_UPGRADE_CHART_PATH:-deploy/helm/platform}"
AUTO_UPGRADE_VALUES_PATH="${PLATFORM_AUTO_UPGRADE_VALUES_PATH:-deploy/helm/platform/values.yaml}"
AUTO_UPGRADE_TIMEOUT="${PLATFORM_AUTO_UPGRADE_TIMEOUT:-10m}"
AUTO_UPGRADE_HISTORY_MAX="${PLATFORM_AUTO_UPGRADE_HISTORY_MAX:-5}"
AUTO_UPGRADE_TAKE_OWNERSHIP="${PLATFORM_AUTO_UPGRADE_TAKE_OWNERSHIP:-true}"
AUTO_UPGRADE_SUSPEND="${PLATFORM_AUTO_UPGRADE_SUSPEND:-true}"
DATABASE_URL="${PLATFORM_DATABASE_URL:-}"
NETUID="${PLATFORM_NETUID:-0}"
CHAIN_ENDPOINT="${PLATFORM_CHAIN_ENDPOINT:-}"
BROKER_ALLOWED_IMAGES="${PLATFORM_BROKER_ALLOWED_IMAGES:-ghcr.io/platformnetwork/}"
MASTER_ADMIN_PORT="${PLATFORM_MASTER_ADMIN_PORT:-8000}"
MASTER_PROXY_PORT="${PLATFORM_MASTER_PROXY_PORT:-8080}"
BROKER_PORT="${PLATFORM_MASTER_BROKER_PORT:-8082}"
CLEANUP_ONLY=0

FOUNDATION_WARNING="Foundation-only installer for Cortex Foundation master infrastructure. Do not run this for validators or third-party operators."

usage() {
  cat <<USAGE
Usage: scripts/install-master.sh [options]

${FOUNDATION_WARNING}

Options:
  --cleanup                  Delete this installer-managed master deployment and exit.
  --namespace NAME           Kubernetes namespace. Default: platform-master
  --image IMAGE              Platform master image. Default: ghcr.io/platformnetwork/platform-master:latest
  --auto-upgrade-schedule S  Cron schedule for full Helm upgrades. Default: */5 * * * *
  --auto-upgrade-helm-image IMAGE  Helm image used by the upgrader CronJob. Default: alpine/helm:3.15.4
  --auto-upgrade-repo REPO   GitHub repo for Helm chart source. Default: PlatformNetwork/platform
  --auto-upgrade-ref REF     Git ref for Helm chart source. Default: main
  --auto-upgrade-chart-path PATH  Chart path inside the repo. Default: deploy/helm/platform
  --auto-upgrade-suspend BOOL  Suspend the Helm upgrader CronJob. Default: true
  --database-url URL         Master PostgreSQL URL.
  --netuid NETUID            Bittensor subnet UID. Default: 0
  --chain-endpoint ENDPOINT  Optional Bittensor chain endpoint.
  --broker-allowed-images P  Comma-separated image prefixes. Default: ghcr.io/platformnetwork/
  -h, --help                 Show this help.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cleanup) CLEANUP_ONLY=1 ;;
    --namespace) NAMESPACE="${2:?missing NAME}"; shift ;;
    --image) IMAGE="${2:?missing IMAGE}"; shift ;;
    --auto-upgrade-schedule) AUTO_UPGRADE_SCHEDULE="${2:?missing SCHEDULE}"; shift ;;
    --auto-upgrade-helm-image) AUTO_UPGRADE_HELM_IMAGE="${2:?missing IMAGE}"; shift ;;
    --auto-upgrade-repo) AUTO_UPGRADE_REPO="${2:?missing REPO}"; shift ;;
    --auto-upgrade-ref) AUTO_UPGRADE_REF="${2:?missing REF}"; shift ;;
    --auto-upgrade-chart-path) AUTO_UPGRADE_CHART_PATH="${2:?missing PATH}"; shift ;;
    --auto-upgrade-suspend) AUTO_UPGRADE_SUSPEND="${2:?missing BOOL}"; shift ;;
    --database-url) DATABASE_URL="${2:?missing URL}"; shift ;;
    --netuid) NETUID="${2:?missing NETUID}"; shift ;;
    --chain-endpoint) CHAIN_ENDPOINT="${2:?missing ENDPOINT}"; shift ;;
    --broker-allowed-images) BROKER_ALLOWED_IMAGES="${2:?missing PREFIXES}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$NAMESPACE" = "platform-validator" ]; then
  echo "platform-validator is reserved for the validator installer" >&2
  exit 2
fi

validate_identifier() {
  local name="$1"
  local value="$2"
  case "$value" in
    ""|*[!A-Za-z0-9_.-]*)
      echo "$name must contain only letters, numbers, dot, underscore, or dash" >&2
      exit 2
      ;;
  esac
}

validate_regex() {
  local name="$1"
  local value="$2"
  local pattern="$3"
  local expectation="$4"
  if [[ ! "$value" =~ $pattern ]]; then
    echo "$name must $expectation" >&2
    exit 2
  fi
}

validate_identifier "namespace" "$NAMESPACE"
validate_regex "auto-upgrade schedule" "$AUTO_UPGRADE_SCHEDULE" '^[A-Za-z0-9*?, /@._-]+$' "use cron-safe characters"
validate_regex "auto-upgrade Helm image" "$AUTO_UPGRADE_HELM_IMAGE" '^[A-Za-z0-9_./:@-]+$' "be an image reference"
validate_regex "auto-upgrade repository" "$AUTO_UPGRADE_REPO" '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' "use owner/repo"
validate_regex "auto-upgrade ref" "$AUTO_UPGRADE_REF" '^[A-Za-z0-9_./-]+$' "use git ref-safe characters"
validate_regex "auto-upgrade chart path" "$AUTO_UPGRADE_CHART_PATH" '^[A-Za-z0-9_./-]+$' "use relative path-safe characters"
validate_regex "auto-upgrade values path" "$AUTO_UPGRADE_VALUES_PATH" '^[A-Za-z0-9_./-]+$' "use relative path-safe characters"
validate_regex "auto-upgrade timeout" "$AUTO_UPGRADE_TIMEOUT" '^[0-9]+[smh]$' "use a Helm duration such as 10m"
validate_regex "auto-upgrade history max" "$AUTO_UPGRADE_HISTORY_MAX" '^[0-9]+$' "be a positive integer"
validate_regex "auto-upgrade take ownership" "$AUTO_UPGRADE_TAKE_OWNERSHIP" '^(true|false)$' "be true or false"
validate_regex "auto-upgrade suspend" "$AUTO_UPGRADE_SUSPEND" '^(true|false)$' "be true or false"

require_kubectl() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl is required" >&2
    exit 1
  fi
}

kubectl_apply() {
  kubectl apply -f -
}

kubectl_delete() {
  kubectl "$@" || true
}

render_broker_allowed_images() {
  local old_ifs="$IFS"
  local prefix
  IFS=','
  for prefix in $BROKER_ALLOWED_IMAGES; do
    IFS="$old_ifs"
    prefix="${prefix#${prefix%%[![:space:]]*}}"
    prefix="${prefix%${prefix##*[![:space:]]}}"
    if [ -n "$prefix" ]; then
      printf '        - "%s"\n' "$prefix"
    fi
    IFS=','
  done
  IFS="$old_ifs"
}

cleanup_master() {
  kubectl_delete -n "$NAMESPACE" delete cronjob "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete cronjob "$APP-config-sync"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-config-sync"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-config-sync"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP-config-sync"
  kubectl_delete -n "$NAMESPACE" delete deployment "$APP-admin"
  kubectl_delete -n "$NAMESPACE" delete deployment "$APP-proxy"
  kubectl_delete -n "$NAMESPACE" delete deployment "$APP-broker"
  kubectl_delete -n "$NAMESPACE" delete service "$APP-admin"
  kubectl_delete -n "$NAMESPACE" delete service "$APP-proxy"
  kubectl_delete -n "$NAMESPACE" delete service "$APP-broker"
  kubectl_delete -n "$NAMESPACE" delete configmap "$APP-config"
  kubectl_delete -n "$NAMESPACE" delete secret "$APP-database-url"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-runtime"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-runtime"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP"
}

render_deployment() {
  local name="$1"
  local component="$2"
  local port="$3"
  local command_name="$4"
  local token_mount="$5"
  local automount="false"
  if [ "$token_mount" = "true" ]; then
    automount="true"
  fi
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: ${component}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: platform-network
      app.kubernetes.io/part-of: ${APP}
      platform.component: ${component}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: platform-network
        app.kubernetes.io/part-of: ${APP}
        platform.component: ${component}
    spec:
      serviceAccountName: ${APP}
      automountServiceAccountToken: ${automount}
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: ${component}
          image: ${IMAGE}
          imagePullPolicy: Always
          command:
            - platform
            - master
            - ${command_name}
            - --config
            - config/master.kubernetes.yaml
          ports:
            - name: http
              containerPort: ${port}
          env:
            - name: PLATFORM_DATABASE__URL
              valueFrom:
                secretKeyRef:
                  name: platform-master-database-url
                  key: url
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: config
              mountPath: /app/config/master.kubernetes.yaml
              subPath: master.yaml
              readOnly: true
            - name: state
              mountPath: /var/lib/platform
      volumes:
        - name: config
          configMap:
            name: ${APP}-config
        - name: state
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: ${component}
spec:
  selector:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: ${component}
  ports:
    - name: http
      port: ${port}
      targetPort: http
YAML
}

render_manifests() {
  cat <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${APP}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${APP}-config-sync
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${APP}-runtime
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
rules:
  - apiGroups: [""]
    resources: ["secrets", "services", "pods", "pods/log", "persistentvolumeclaims", "configmaps"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${APP}-config-sync
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["${APP}-config"]
    verbs: ["get", "patch", "update"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    resourceNames: ["${APP}-admin", "${APP}-proxy", "${APP}-broker"]
    verbs: ["get", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${APP}-runtime
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
subjects:
  - kind: ServiceAccount
    name: ${APP}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${APP}-runtime
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${APP}-config-sync
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
subjects:
  - kind: ServiceAccount
    name: ${APP}-config-sync
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${APP}-config-sync
---
apiVersion: v1
kind: Secret
metadata:
  name: platform-master-database-url
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
type: Opaque
stringData:
  url: "${DATABASE_URL}"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${APP}-config
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
data:
  master.yaml: |
    environment: "development"
    runtime:
      backend: "kubernetes"
    database:
      url: "\${PLATFORM_DATABASE__URL}"
    network:
      netuid: ${NETUID}
      chain_endpoint: "${CHAIN_ENDPOINT}"
    master:
      registry_url: "http://${APP}-admin:${MASTER_ADMIN_PORT}"
      admin_host: "0.0.0.0"
      admin_port: ${MASTER_ADMIN_PORT}
      proxy_host: "0.0.0.0"
      proxy_port: ${MASTER_PROXY_PORT}
    docker:
      broker_host: "0.0.0.0"
      broker_port: ${BROKER_PORT}
      broker_url: "http://${APP}-broker:${BROKER_PORT}"
      broker_allowed_images:
$(render_broker_allowed_images)
    kubernetes:
      namespace: "${NAMESPACE}"
      in_cluster: true
      target_state_file: "/var/lib/platform/kubernetes_targets.json"
      service_account: "${APP}"
      challenge_mode: "statefulset"
      broker_backend: "kubernetes"
      storage_size: "10Gi"
    observability:
      log_json: true
      otel_service_name: "platform-master"
---
YAML
  render_deployment "${APP}-admin" "master-admin" "$MASTER_ADMIN_PORT" "run" "true"
  echo "---"
  render_deployment "${APP}-proxy" "master-proxy" "$MASTER_PROXY_PORT" "proxy" "false"
  echo "---"
  render_deployment "${APP}-broker" "master-broker" "$BROKER_PORT" "broker" "true"
  echo "---"
  render_helm_upgrader
}

render_helm_upgrade_command() {
  cat <<SCRIPT
set -eu
WORKDIR="\$(mktemp -d)"
trap 'rm -rf "\${WORKDIR}"' EXIT
mkdir -p "\${WORKDIR}/source"
wget -qO "\${WORKDIR}/source.tar.gz" "https://codeload.github.com/${AUTO_UPGRADE_REPO}/tar.gz/${AUTO_UPGRADE_REF}"
tar -xzf "\${WORKDIR}/source.tar.gz" -C "\${WORKDIR}/source" --strip-components=1
set -- upgrade --install ${APP} "\${WORKDIR}/source/${AUTO_UPGRADE_CHART_PATH}" \
  -f "\${WORKDIR}/source/${AUTO_UPGRADE_VALUES_PATH}" \
  --namespace ${NAMESPACE} \
  --create-namespace \
  --atomic \
  --wait \
  --cleanup-on-fail \
  --history-max ${AUTO_UPGRADE_HISTORY_MAX} \
  --timeout ${AUTO_UPGRADE_TIMEOUT}
if [ "${AUTO_UPGRADE_TAKE_OWNERSHIP}" = "true" ]; then
  set -- "\$@" --take-ownership
fi
helm "\$@" \
  --set autoUpgrade.enabled=true \
  --set autoUpgrade.mode=master \
  --set master.enabled=true \
  --set validator.enabled=false \
  --set imageAutoUpdate.enabled=false \
  --set configSync.enabled=false \
  --set-string database.urlSecret.name="platform-master-database-url" \
  --set-string database.urlSecret.key="url" \
  --set-string security.existingSecret="platform-secrets" \
  --set-string kubernetes.namespace="${NAMESPACE}" \
  --set-string kubernetes.serviceAccount="${APP}"
SCRIPT
}

render_helm_upgrader() {
  local command
  command="$(render_helm_upgrade_command | sed 's/^/                  /')"
  cat <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: helm-upgrader
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: helm-upgrader
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: [""]
    resources: ["services", "serviceaccounts", "persistentvolumeclaims", "pods"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["batch"]
    resources: ["cronjobs", "jobs"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies", "ingresses"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: helm-upgrader
subjects:
  - kind: ServiceAccount
    name: ${APP}-helm-upgrader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${APP}-helm-upgrader
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: helm-upgrader
spec:
  schedule: "${AUTO_UPGRADE_SCHEDULE}"
  suspend: ${AUTO_UPGRADE_SUSPEND}
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app.kubernetes.io/name: platform-network
            app.kubernetes.io/part-of: ${APP}
            platform.component: helm-upgrader
        spec:
          serviceAccountName: ${APP}-helm-upgrader
          automountServiceAccountToken: true
          restartPolicy: OnFailure
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: helm-upgrader
              image: ${AUTO_UPGRADE_HELM_IMAGE}
              imagePullPolicy: Always
              env:
                - name: HELM_DRIVER
                  value: configmap
              command:
                - sh
                - -ec
                - |
${command}
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop: ["ALL"]
YAML
}

main() {
  require_kubectl
  echo "$FOUNDATION_WARNING"
  if [ "$CLEANUP_ONLY" -eq 1 ]; then
    cleanup_master
    exit 0
  fi

  if [ -z "$DATABASE_URL" ]; then
    echo "database-url is required; provide --database-url or PLATFORM_DATABASE_URL" >&2
    exit 2
  fi

  render_manifests | kubectl_apply
  echo "Master Kubernetes install complete."
  echo "Namespace: ${NAMESPACE}"
  echo "Logs: kubectl -n ${NAMESPACE} logs -f deployment/${APP}-admin"
}

main "$@"
