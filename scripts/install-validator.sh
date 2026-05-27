#!/usr/bin/env bash
set -euo pipefail
umask 077

APP="platform-validator"
NAMESPACE="${PLATFORM_NAMESPACE:-platform-validator}"
IMAGE="${PLATFORM_IMAGE:-ghcr.io/platformnetwork/platform:latest}"
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
IMAGE_UPDATE_SCHEDULE="${PLATFORM_IMAGE_UPDATE_SCHEDULE:-*/1 * * * *}"
IMAGE_UPDATER_IMAGE="${PLATFORM_IMAGE_UPDATER_IMAGE:-ghcr.io/platformnetwork/platform:latest}"
IMAGE_UPDATE_REGISTRY_ENDPOINT="${PLATFORM_IMAGE_UPDATE_REGISTRY_ENDPOINT:-}"
DATABASE_URL_SECRET_NAME="${PLATFORM_DATABASE_URL_SECRET_NAME:-platform-validator-database-url}"
DATABASE_URL_SECRET_KEY="${PLATFORM_DATABASE_URL_SECRET_KEY:-url}"
REGISTRY_URL="${PLATFORM_VALIDATOR_REGISTRY_URL:-https://chain.platform.network}"
NETUID="${PLATFORM_NETUID:-100}"
CHAIN_ENDPOINT="${PLATFORM_CHAIN_ENDPOINT:-}"
WALLET_NAME="${PLATFORM_WALLET_NAME:-platform-validator}"
WALLET_HOTKEY="${PLATFORM_WALLET_HOTKEY:-validator}"
WALLET_PATH="/var/lib/platform/wallets"
STORAGE_SIZE="${PLATFORM_VALIDATOR_STORAGE_SIZE:-10Gi}"
DATABASE_URL="${PLATFORM_DATABASE_URL:-}"
BROKER_ALLOWED_IMAGES="${PLATFORM_BROKER_ALLOWED_IMAGES:-ghcr.io/platformnetwork/}"
CLEANUP_ONLY=0
TMP_DIR=""
PYTHON_CMD=()

usage() {
  cat <<'USAGE'
Usage: scripts/install-validator.sh [options]

Kubernetes-only validator installer. It asks only for the validator hotkey mnemonic.

Options:
  --cleanup                  Delete this installer-managed validator deployment and exit.
  --namespace NAME           Kubernetes namespace. Default: platform-validator
  --image IMAGE              Platform validator image. Default: ghcr.io/platformnetwork/platform:latest
  --auto-upgrade-schedule S  Cron schedule for full Helm upgrades. Default: */5 * * * *
  --auto-upgrade-helm-image IMAGE  Helm image used by the upgrader CronJob. Default: alpine/helm:3.15.4
  --auto-upgrade-repo REPO   GitHub repo for Helm chart source. Default: PlatformNetwork/platform
  --auto-upgrade-ref REF     Git ref for Helm chart source. Default: main
  --auto-upgrade-chart-path PATH  Chart path inside the repo. Default: deploy/helm/platform
  --auto-upgrade-suspend BOOL  Suspend the Helm upgrader CronJob. Default: true
  --image-update-schedule S    Cron schedule for image digest refreshes. Default: */1 * * * *
  --image-updater-image IMAGE  Image used by the image updater CronJob. Default: ghcr.io/platformnetwork/platform:latest
  --database-url-secret-name NAME  Database URL Secret name for Helm upgrades. Default: platform-validator-database-url
  --database-url-secret-key KEY    Database URL Secret key for Helm upgrades. Default: url
  --registry-url URL         Registry API URL. Default: https://chain.platform.network
  --netuid NETUID            Bittensor subnet UID. Default: 100
  --chain-endpoint ENDPOINT  Optional Bittensor chain endpoint.
  --wallet-name NAME         Wallet name. Default: platform-validator
  --wallet-hotkey NAME       Hotkey label. Default: validator
  --storage-size SIZE        Validator state PVC size. Default: 10Gi
  --database-url URL         Policy-only database URL for settings validation.
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
    --image-update-schedule) IMAGE_UPDATE_SCHEDULE="${2:?missing SCHEDULE}"; shift ;;
    --image-updater-image) IMAGE_UPDATER_IMAGE="${2:?missing IMAGE}"; shift ;;
    --database-url-secret-name) DATABASE_URL_SECRET_NAME="${2:?missing NAME}"; shift ;;
    --database-url-secret-key) DATABASE_URL_SECRET_KEY="${2:?missing KEY}"; shift ;;
    --registry-url) REGISTRY_URL="${2:?missing URL}"; shift ;;
    --netuid) NETUID="${2:?missing NETUID}"; shift ;;
    --chain-endpoint) CHAIN_ENDPOINT="${2:?missing ENDPOINT}"; shift ;;
    --wallet-name) WALLET_NAME="${2:?missing NAME}"; shift ;;
    --wallet-hotkey) WALLET_HOTKEY="${2:?missing NAME}"; shift ;;
    --storage-size) STORAGE_SIZE="${2:?missing SIZE}"; shift ;;
    --database-url) DATABASE_URL="${2:?missing URL}"; shift ;;
    --broker-allowed-images) BROKER_ALLOWED_IMAGES="${2:?missing PREFIXES}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

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
validate_identifier "database URL Secret name" "$DATABASE_URL_SECRET_NAME"
validate_identifier "database URL Secret key" "$DATABASE_URL_SECRET_KEY"
validate_identifier "wallet name" "$WALLET_NAME"
validate_identifier "wallet hotkey" "$WALLET_HOTKEY"
validate_regex "auto-upgrade schedule" "$AUTO_UPGRADE_SCHEDULE" '^[A-Za-z0-9*?, /@._-]+$' "use cron-safe characters"
validate_regex "auto-upgrade Helm image" "$AUTO_UPGRADE_HELM_IMAGE" '^[A-Za-z0-9_./:@-]+$' "be an image reference"
validate_regex "image updater image" "$IMAGE_UPDATER_IMAGE" '^[A-Za-z0-9_./:@-]+$' "be an image reference"
validate_regex "auto-upgrade repository" "$AUTO_UPGRADE_REPO" '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' "use owner/repo"
validate_regex "auto-upgrade ref" "$AUTO_UPGRADE_REF" '^[A-Za-z0-9_./-]+$' "use git ref-safe characters"
validate_regex "auto-upgrade chart path" "$AUTO_UPGRADE_CHART_PATH" '^[A-Za-z0-9_./-]+$' "use relative path-safe characters"
validate_regex "auto-upgrade values path" "$AUTO_UPGRADE_VALUES_PATH" '^[A-Za-z0-9_./-]+$' "use relative path-safe characters"
validate_regex "auto-upgrade timeout" "$AUTO_UPGRADE_TIMEOUT" '^[0-9]+[smh]$' "use a Helm duration such as 10m"
validate_regex "image update schedule" "$IMAGE_UPDATE_SCHEDULE" '^[A-Za-z0-9*?, /@._-]+$' "use cron-safe characters"
validate_regex "auto-upgrade history max" "$AUTO_UPGRADE_HISTORY_MAX" '^[0-9]+$' "be a positive integer"
validate_regex "auto-upgrade take ownership" "$AUTO_UPGRADE_TAKE_OWNERSHIP" '^(true|false)$' "be true or false"
validate_regex "auto-upgrade suspend" "$AUTO_UPGRADE_SUSPEND" '^(true|false)$' "be true or false"

cleanup_tmp() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup_tmp EXIT

require_kubectl() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl is required" >&2
    exit 1
  fi
}

select_hotkey_python() {
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import bittensor' >/dev/null 2>&1; then
    PYTHON_CMD=(python3)
    return
  fi
  if command -v uv >/dev/null 2>&1 && uv run python -c 'import bittensor' >/dev/null 2>&1; then
    PYTHON_CMD=(uv run python)
    return
  fi
  echo "python with bittensor is required to import the hotkey mnemonic" >&2
  exit 1
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

cleanup_validator() {
  kubectl_delete -n "$NAMESPACE" delete cronjob "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP-helm-upgrader"
  kubectl_delete -n "$NAMESPACE" delete cronjob "$APP-image-updater"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-image-updater"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-image-updater"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP-image-updater"
  kubectl_delete -n "$NAMESPACE" delete deployment "$APP"
  kubectl_delete -n "$NAMESPACE" delete configmap "$APP-config"
  kubectl_delete -n "$NAMESPACE" delete secret "$DATABASE_URL_SECRET_NAME"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-runtime"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-runtime"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP"
}

import_hotkey_secret() {
  printf 'Validator hotkey mnemonic: '
  IFS= read -r -s HOTKEY_MNEMONIC
  printf '\n'
  if [ -z "$HOTKEY_MNEMONIC" ]; then
    echo "Hotkey mnemonic cannot be empty" >&2
    exit 1
  fi

  TMP_DIR="$(mktemp -d)"
  export TMP_DIR WALLET_NAME WALLET_HOTKEY
  printf '%s\n' "$HOTKEY_MNEMONIC" | "${PYTHON_CMD[@]}" -c '
import os
import sys
from pathlib import Path
import bittensor

mnemonic = sys.stdin.readline().strip()
if not mnemonic:
    raise SystemExit("missing hotkey mnemonic")
root = Path(os.environ["TMP_DIR"])
wallet_name = os.environ["WALLET_NAME"]
hotkey_name = os.environ["WALLET_HOTKEY"]
wallet = bittensor.Wallet(
    name=wallet_name,
    hotkey=hotkey_name,
    path=str(root / "wallets"),
)
wallet.regenerate_hotkey(
    mnemonic=mnemonic,
    use_password=False,
    overwrite=True,
    suppress=True,
)
'
  HOTKEY_MNEMONIC=""
  unset HOTKEY_MNEMONIC

  HOTKEY_DIR="$TMP_DIR/wallets/$WALLET_NAME/hotkeys"
  kubectl -n "$NAMESPACE" create secret generic "$APP-wallet" \
    --from-file=hotkey="$HOTKEY_DIR/$WALLET_HOTKEY" \
    --from-file=hotkeypub.txt="$HOTKEY_DIR/${WALLET_HOTKEY}pub.txt" \
    --dry-run=client \
    -o yaml | kubectl_apply
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
  --set autoUpgrade.suspend=${AUTO_UPGRADE_SUSPEND} \
  --set autoUpgrade.mode=validator \
  --set master.enabled=false \
  --set validator.enabled=true \
  --set imageAutoUpdate.enabled=false \
  --set configSync.enabled=false \
  --set-string database.urlSecret.name="${DATABASE_URL_SECRET_NAME}" \
  --set-string database.urlSecret.key="${DATABASE_URL_SECRET_KEY}" \
  --set-string kubernetes.namespace="${NAMESPACE}" \
  --set-string validator.walletSecretName="${APP}-wallet" \
  --set-string network.walletName="${WALLET_NAME}" \
  --set-string network.walletHotkey="${WALLET_HOTKEY}" \
  --set-string validator.deploymentNameOverride="${APP}" \
  --set-string persistence.existingClaim="${APP}-state"
SCRIPT
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
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: helm-upgrader
automountServiceAccountToken: true
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${APP}-image-updater
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: image-updater
automountServiceAccountToken: true
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
    resources: ["secrets", "services", "pods", "pods/log", "persistentvolumeclaims"]
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
  name: ${APP}-image-updater
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: image-updater
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    resourceNames: ["${APP}"]
    verbs: ["get", "patch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
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
  name: ${APP}-image-updater
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: image-updater
subjects:
  - kind: ServiceAccount
    name: ${APP}-image-updater
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${APP}-image-updater
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${APP}-helm-upgrader
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
subjects:
  - kind: ServiceAccount
    name: ${APP}-helm-upgrader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${APP}-helm-upgrader
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${APP}-state
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: ${STORAGE_SIZE}
---
apiVersion: v1
kind: Secret
metadata:
  name: ${DATABASE_URL_SECRET_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
type: Opaque
stringData:
  ${DATABASE_URL_SECRET_KEY}: "${DATABASE_URL}"
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
  validator.yaml: |
    environment: "development"
    runtime:
      backend: "kubernetes"
    database:
      url: "\${PLATFORM_DATABASE__URL}"
    network:
      netuid: ${NETUID}
      chain_endpoint: "${CHAIN_ENDPOINT}"
      wallet_name: "${WALLET_NAME}"
      wallet_hotkey: "${WALLET_HOTKEY}"
      wallet_path: "${WALLET_PATH}"
      master_uid: 0
    validator:
      registry_url: "${REGISTRY_URL}"
      registry_retry_seconds: 15
    docker:
      broker_url: "http://platform-validator-broker:8082"
      secret_dir: "/var/lib/platform/secrets"
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
      otel_service_name: "platform-validator"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: validator
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: platform-network
      app.kubernetes.io/part-of: ${APP}
      platform.component: validator
  template:
    metadata:
      labels:
        app.kubernetes.io/name: platform-network
        app.kubernetes.io/part-of: ${APP}
        platform.component: validator
    spec:
      serviceAccountName: ${APP}
      automountServiceAccountToken: true
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: validator
          image: ${IMAGE}
          imagePullPolicy: Always
          env:
            - name: PLATFORM_DATABASE__URL
              valueFrom:
                secretKeyRef:
                  name: ${DATABASE_URL_SECRET_NAME}
                  key: ${DATABASE_URL_SECRET_KEY}
          command:
            - platform
            - validator
            - run
            - --config
            - config/validator.kubernetes.yaml
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: config
              mountPath: /app/config/validator.kubernetes.yaml
              subPath: validator.yaml
              readOnly: true
            - name: state
              mountPath: /var/lib/platform
            - name: wallet
              mountPath: ${WALLET_PATH}/${WALLET_NAME}/hotkeys
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: ${APP}-config
        - name: state
          persistentVolumeClaim:
            claimName: ${APP}-state
        - name: wallet
          secret:
            secretName: ${APP}-wallet
            items:
              - key: hotkey
                path: ${WALLET_HOTKEY}
              - key: hotkeypub.txt
                path: ${WALLET_HOTKEY}pub.txt
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ${APP}-image-updater
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: platform-network
    app.kubernetes.io/part-of: ${APP}
    platform.component: image-updater
spec:
  schedule: "${IMAGE_UPDATE_SCHEDULE}"
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
            platform.component: image-updater
        spec:
          serviceAccountName: ${APP}-image-updater
          automountServiceAccountToken: true
          restartPolicy: OnFailure
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: image-updater
              image: ${IMAGE_UPDATER_IMAGE}
              imagePullPolicy: Always
              command:
                - platform
                - validator
                - refresh-image
                - --namespace
                - ${NAMESPACE}
                - --resource-kind
                - deployment
                - --name
                - ${APP}
                - --container
                - validator
                - --image
                - ${IMAGE}
                - --registry-endpoint
                - "${IMAGE_UPDATE_REGISTRY_ENDPOINT}"
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop: ["ALL"]
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
$(render_helm_upgrade_command | sed 's/^/                  /')
              volumeMounts:
                - name: kube-api-access
                  mountPath: /var/run/secrets/kubernetes.io/serviceaccount
                  readOnly: true
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop: ["ALL"]
          volumes:
            - name: kube-api-access
              projected:
                defaultMode: 420
                sources:
                  - serviceAccountToken:
                      path: token
                      expirationSeconds: 3600
                  - configMap:
                      name: kube-root-ca.crt
                      items:
                        - key: ca.crt
                          path: ca.crt
                  - downwardAPI:
                      items:
                        - path: namespace
                          fieldRef:
                            apiVersion: v1
                            fieldPath: metadata.namespace
YAML
}

main() {
  require_kubectl
  if [ "$CLEANUP_ONLY" -eq 1 ]; then
    cleanup_validator
    exit 0
  fi

  if [ -z "$DATABASE_URL" ]; then
    echo "database-url is required; provide --database-url or PLATFORM_DATABASE_URL" >&2
    exit 2
  fi

  select_hotkey_python
  render_manifests | kubectl_apply
  import_hotkey_secret
  echo "Validator Kubernetes install complete."
  echo "Logs: kubectl -n ${NAMESPACE} logs -f deployment/${APP}"
}

main "$@"
