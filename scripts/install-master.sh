#!/usr/bin/env bash
set -euo pipefail
umask 077

APP="platform-master"
NAMESPACE="${PLATFORM_NAMESPACE:-platform-master}"
IMAGE="${PLATFORM_MASTER_IMAGE:-ghcr.io/platformnetwork/platform-master:latest}"
CONFIG_SYNC_IMAGE="${PLATFORM_MASTER_CONFIG_SYNC_IMAGE:-}"
CONFIG_SYNC_SCHEDULE="${PLATFORM_MASTER_CONFIG_SYNC_SCHEDULE:-*/1 * * * *}"
CONFIG_SYNC_REPO="${PLATFORM_MASTER_CONFIG_SYNC_REPO:-PlatformNetwork/platform}"
CONFIG_SYNC_REF="${PLATFORM_MASTER_CONFIG_SYNC_REF:-main}"
DATABASE_URL="${PLATFORM_DATABASE_URL:-postgresql+asyncpg://platform-master.invalid/platform}"
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
  --config-sync-image IMAGE  Image used by the config sync CronJob. Default: same as --image
  --config-sync-schedule S   Cron schedule for config sync. Default: */1 * * * *
  --config-sync-repo REPO    GitHub repo for config sync. Default: PlatformNetwork/platform
  --config-sync-ref REF      Git ref for config sync. Default: main
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
    --config-sync-image) CONFIG_SYNC_IMAGE="${2:?missing IMAGE}"; shift ;;
    --config-sync-schedule) CONFIG_SYNC_SCHEDULE="${2:?missing SCHEDULE}"; shift ;;
    --config-sync-repo) CONFIG_SYNC_REPO="${2:?missing REPO}"; shift ;;
    --config-sync-ref) CONFIG_SYNC_REF="${2:?missing REF}"; shift ;;
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

if [ -z "$CONFIG_SYNC_IMAGE" ]; then
  CONFIG_SYNC_IMAGE="$IMAGE"
fi

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
              value: "${DATABASE_URL}"
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
    resources: ["services", "pods", "pods/log", "persistentvolumeclaims", "configmaps"]
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
      url: "${DATABASE_URL}"
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
  cat <<YAML
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ${APP}-config-sync
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: master-config-sync
spec:
  schedule: "${CONFIG_SYNC_SCHEDULE}"
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
            platform.component: master-config-sync
        spec:
          serviceAccountName: ${APP}-config-sync
          automountServiceAccountToken: true
          restartPolicy: OnFailure
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: config-sync
              image: ${CONFIG_SYNC_IMAGE}
              imagePullPolicy: Always
              command:
                - platform
                - kubernetes
                - sync-config
                - --namespace
                - ${NAMESPACE}
                - --config-map
                - ${APP}-config
                - --repo
                - ${CONFIG_SYNC_REPO}
                - --ref
                - ${CONFIG_SYNC_REF}
                - --rollout-target
                - Deployment/${APP}-admin
                - --rollout-target
                - Deployment/${APP}-proxy
                - --rollout-target
                - Deployment/${APP}-broker
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

  cleanup_master
  render_manifests | kubectl_apply
  echo "Master Kubernetes install complete."
  echo "Namespace: ${NAMESPACE}"
  echo "Logs: kubectl -n ${NAMESPACE} logs -f deployment/${APP}-admin"
}

main "$@"
