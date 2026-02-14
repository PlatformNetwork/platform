#!/bin/bash
set -euo pipefail

log() {
    echo "[docker-install] $1"
}

has_docker() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

has_compose() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        return 0
    fi

    command -v docker-compose >/dev/null 2>&1
}

if has_docker && has_compose; then
    log "Docker and Compose already available"
    exit 0
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        log "sudo is required to install Docker"
        exit 1
    fi
fi

start_docker() {
    if command -v systemctl >/dev/null 2>&1; then
        ${SUDO} systemctl enable --now docker || ${SUDO} systemctl start docker
        return
    fi

    if command -v service >/dev/null 2>&1; then
        ${SUDO} service docker start
        return
    fi

    if command -v rc-service >/dev/null 2>&1; then
        ${SUDO} rc-service docker start
    fi
}

install_debian() {
    local repo_id
    local codename

    repo_id="${ID}"
    case "${ID}" in
        linuxmint|pop|neon)
            repo_id="ubuntu"
            ;;
        raspbian)
            repo_id="debian"
            ;;
    esac

    ${SUDO} apt-get update -y
    ${SUDO} apt-get install -y ca-certificates curl gnupg lsb-release
    ${SUDO} install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${repo_id}/gpg" | ${SUDO} gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    ${SUDO} chmod a+r /etc/apt/keyrings/docker.gpg

    codename="${VERSION_CODENAME:-}"
    if [ -z "${codename}" ] && [ -n "${UBUNTU_CODENAME:-}" ]; then
        codename="${UBUNTU_CODENAME}"
    fi
    if [ -z "${codename}" ]; then
        codename="$(lsb_release -cs)"
    fi

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${repo_id} ${codename} stable" | ${SUDO} tee /etc/apt/sources.list.d/docker.list >/dev/null
    ${SUDO} apt-get update -y
    ${SUDO} apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_fedora() {
    ${SUDO} dnf -y install dnf-plugins-core ca-certificates curl
    ${SUDO} dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    ${SUDO} dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_rhel() {
    local pkg_mgr

    if command -v dnf >/dev/null 2>&1; then
        pkg_mgr=dnf
    else
        pkg_mgr=yum
    fi

    ${SUDO} ${pkg_mgr} -y install ca-certificates curl
    ${SUDO} ${pkg_mgr} -y install dnf-plugins-core || true
    ${SUDO} ${pkg_mgr} config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    ${SUDO} ${pkg_mgr} -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_amzn() {
    if command -v amazon-linux-extras >/dev/null 2>&1; then
        ${SUDO} amazon-linux-extras install -y docker
    else
        ${SUDO} yum -y install docker
    fi
    ${SUDO} yum -y install docker-compose-plugin || ${SUDO} yum -y install docker-compose
}

install_arch() {
    ${SUDO} pacman -Sy --noconfirm docker docker-compose
}

install_alpine() {
    ${SUDO} apk add --no-cache docker docker-cli-compose docker-compose
}

if [[ "${OSTYPE}" == "darwin"* ]]; then
    if ! command -v brew >/dev/null 2>&1; then
        log "Homebrew is required to install Docker Desktop"
        exit 1
    fi
    brew install --cask docker
    exit 0
fi

if [ ! -f /etc/os-release ]; then
    log "Unsupported OS: /etc/os-release not found"
    exit 1
fi

. /etc/os-release

case "${ID}" in
    ubuntu|debian|linuxmint|raspbian|pop|neon)
        install_debian
        ;;
    fedora)
        install_fedora
        ;;
    centos|rhel|almalinux|rocky)
        install_rhel
        ;;
    amzn)
        install_amzn
        ;;
    arch|manjaro)
        install_arch
        ;;
    alpine)
        install_alpine
        ;;
    *)
        if [[ "${ID_LIKE:-}" == *"debian"* ]]; then
            install_debian
        elif [[ "${ID_LIKE:-}" == *"rhel"* ]] || [[ "${ID_LIKE:-}" == *"fedora"* ]]; then
            install_rhel
        else
            log "Unsupported Linux distribution: ${ID}"
            exit 1
        fi
        ;;
 esac

start_docker

if ! has_docker; then
    log "Docker daemon is not available after installation"
    exit 1
fi

if ! has_compose; then
    log "Docker Compose is not available after installation"
    exit 1
fi

log "Docker installation complete"
