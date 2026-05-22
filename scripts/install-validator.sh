#!/usr/bin/env bash
set -euo pipefail
umask 077

APP="platform-validator"
NAMESPACE="${PLATFORM_NAMESPACE:-platform-validator}"
IMAGE="${PLATFORM_IMAGE:-ghcr.io/platformnetwork/platform:latest}"
REGISTRY_URL="${PLATFORM_VALIDATOR_REGISTRY_URL:-https://chain.platform.network}"
NETUID="${PLATFORM_NETUID:-0}"
CHAIN_ENDPOINT="${PLATFORM_CHAIN_ENDPOINT:-}"
WALLET_NAME="${PLATFORM_WALLET_NAME:-platform-validator}"
WALLET_HOTKEY="${PLATFORM_WALLET_HOTKEY:-validator}"
WALLET_PATH="/var/lib/platform/wallets"
STORAGE_SIZE="${PLATFORM_VALIDATOR_STORAGE_SIZE:-10Gi}"
DATABASE_URL="${PLATFORM_DATABASE_URL:-postgresql+asyncpg://platform-validator.invalid/platform}"
BROKER_ALLOWED_IMAGES="${PLATFORM_BROKER_ALLOWED_IMAGES:-ghcr.io/platformnetwork/}"
DRY_RUN=0
CLEANUP_ONLY=0
RENDER_ONLY=0
SKIP_HOTKEY_IMPORT=0
WALLET_SECRET_OPTIONAL="false"
TMP_DIR=""

usage() {
  cat <<'USAGE'
Usage: scripts/install-validator.sh [options]

Kubernetes-only validator installer. It asks only for the validator hotkey mnemonic.

Options:
  --dry-run                  Print kubectl actions without applying them.
  --cleanup                  Delete this installer-managed validator deployment and exit.
  --skip-hotkey-import       Do not prompt for or import a hotkey mnemonic.
  --render-manifests         Print Kubernetes manifests and exit.
  --namespace NAME           Kubernetes namespace. Default: platform-validator
  --image IMAGE              Platform validator image. Default: ghcr.io/platformnetwork/platform:latest
  --registry-url URL         Registry API URL. Default: https://chain.platform.network
  --netuid NETUID            Bittensor subnet UID. Default: 0
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
    --dry-run) DRY_RUN=1 ;;
    --cleanup) CLEANUP_ONLY=1 ;;
    --skip-hotkey-import) SKIP_HOTKEY_IMPORT=1; WALLET_SECRET_OPTIONAL="true" ;;
    --render-manifests) RENDER_ONLY=1 ;;
    --namespace) NAMESPACE="${2:?missing NAME}"; shift ;;
    --image) IMAGE="${2:?missing IMAGE}"; shift ;;
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

cleanup_tmp() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup_tmp EXIT

require_tools() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl is required" >&2
    exit 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to import the hotkey mnemonic" >&2
    exit 1
  fi
}

kubectl_apply() {
  if [ "$DRY_RUN" -eq 1 ]; then
    kubectl apply --dry-run=client -f -
  else
    kubectl apply -f -
  fi
}

kubectl_delete() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run]'
    printf ' %q' kubectl "$@"
    printf '\n'
  else
    kubectl "$@" || true
  fi
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
  kubectl_delete -n "$NAMESPACE" delete deployment "$APP"
  kubectl_delete -n "$NAMESPACE" delete configmap "$APP-config"
  kubectl_delete -n "$NAMESPACE" delete secret "$APP-wallet"
  kubectl_delete -n "$NAMESPACE" delete role "$APP-runtime"
  kubectl_delete -n "$NAMESPACE" delete rolebinding "$APP-runtime"
  kubectl_delete -n "$NAMESPACE" delete serviceaccount "$APP"
}

import_hotkey_secret() {
  if [ "$SKIP_HOTKEY_IMPORT" -eq 1 ]; then
    return
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] would prompt for validator hotkey mnemonic and create Secret ${APP}-wallet"
    return
  fi

  printf 'Validator hotkey mnemonic: '
  IFS= read -r -s HOTKEY_MNEMONIC
  printf '\n'
  if [ -z "$HOTKEY_MNEMONIC" ]; then
    echo "Hotkey mnemonic cannot be empty" >&2
    exit 1
  fi

  TMP_DIR="$(mktemp -d)"
  export TMP_DIR WALLET_NAME WALLET_HOTKEY
  printf '%s\n' "$HOTKEY_MNEMONIC" | python3 -c '
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
    --dry-run=client -o yaml | kubectl apply -f -
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
      url: "${DATABASE_URL}"
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
          imagePullPolicy: IfNotPresent
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
            optional: ${WALLET_SECRET_OPTIONAL}
            items:
              - key: hotkey
                path: ${WALLET_HOTKEY}
              - key: hotkeypub.txt
                path: ${WALLET_HOTKEY}pub.txt
YAML
}

main() {
  require_tools
  if [ "$RENDER_ONLY" -eq 1 ]; then
    render_manifests
    exit 0
  fi

  cleanup_validator
  if [ "$CLEANUP_ONLY" -eq 1 ]; then
    exit 0
  fi

  render_manifests | kubectl_apply
  import_hotkey_secret
  echo "Validator Kubernetes install complete."
  echo "Logs: kubectl -n ${NAMESPACE} logs -f deployment/${APP}"
}

main "$@"
