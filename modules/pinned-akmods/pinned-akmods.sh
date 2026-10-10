#!/usr/bin/env bash
# Derived from the digest-verified upstream module; see UPSTREAM_SOURCE.json.
set -euo pipefail

EXPECTED_KERNEL="7.2.9-200.fc44.x86_64"

pinned_fail() {
    echo "ERROR: pinned-akmods: $*" >&2
    exit 1
}

validate_installed_kernel() {
    local installed_kernel
    installed_kernel=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-core) || pinned_fail "kernel-core query failed"
    [[ "$installed_kernel" == "$EXPECTED_KERNEL" ]] || pinned_fail "installed kernel mismatch: $installed_kernel"
}

validate_pinned_inputs() {
    [[ $# == 1 ]] || pinned_fail "exactly one module configuration is required"
    jq -e '
        type == "object" and .type == "pinned-akmods" and .source == "local" and
        .base == "main" and .install == [] and .["nvidia-driver"] == "nvidia-open" and
        (keys - ["type", "source", "base", "install", "nvidia-driver"] | length == 0)
    ' <<< "$1" >/dev/null || pinned_fail "unsupported module configuration"
    [[ "${OS_VERSION:-}" == "44" ]] || pinned_fail "BlueBuild OS_VERSION must be 44"
    [[ "${MULTILIB:-}" == "0" ]] || pinned_fail "MULTILIB must be disabled"
    [[ "$(rpm -E '%{?fedora}')" == "44" ]] || pinned_fail "Fedora 44 is required"
    [[ "$(rpm -E '%{_arch}')" == "x86_64" ]] || pinned_fail "amd64 is required"
    validate_installed_kernel
}

validate_installed_modules() {
    local kmod_version driver_version module_version vermagic module
    validate_installed_kernel
    kmod_version=$(rpm -q --qf '%{VERSION}\n' kmod-nvidia) || pinned_fail "kmod-nvidia query failed"
    driver_version=$(rpm -q --qf '%{VERSION}\n' nvidia-driver) || pinned_fail "nvidia-driver query failed"
    [[ -n "$kmod_version" && "$kmod_version" == "$driver_version" ]] || pinned_fail "kernel/userspace NVIDIA version mismatch"
    module_version=$(modinfo -k "$EXPECTED_KERNEL" -F version nvidia) || pinned_fail "installed NVIDIA module missing"
    [[ "$module_version" == "$driver_version" ]] || pinned_fail "NVIDIA module version mismatch"
    for module in nvidia nvidia_drm nvidia_modeset nvidia_uvm; do
        vermagic=$(modinfo -k "$EXPECTED_KERNEL" -F vermagic "$module") || pinned_fail "NVIDIA vermagic query failed: $module"
        [[ "${vermagic%% *}" == "$EXPECTED_KERNEL" ]] || pinned_fail "NVIDIA module kernel mismatch: $module"
    done
}

# All following installation commands are unreachable until these checks pass.
validate_pinned_inputs "$@"

ENABLE_AKMODS_REPO() {
  akmods_repo="$(find /etc/yum.repos.d -type f -exec grep -l '\[copr:copr.fedorainfracloud.org:ublue-os:akmods\]' {} +)"
  if [[ -n "${akmods_repo}" ]]; then
    sed -i 's@enabled=0@enabled=1@g' "${akmods_repo}"
  fi
}

INSTALL_RPM_FUSION() {
if ! rpm -q rpmfusion-free-release &>/dev/null && ! rpm -q rpmfusion-nonfree-release &>/dev/null; then
  if command -v dnf5 &> /dev/null; then
    dnf5 -y install \
        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${OS_VERSION}.noarch.rpm" \
        "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${OS_VERSION}.noarch.rpm"
  elif command -v rpm-ostree &> /dev/null; then
    rpm-ostree install \
        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${OS_VERSION}.noarch.rpm" \
        "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${OS_VERSION}.noarch.rpm"
  fi
  previously_not_installed_rpm_fusion=true
else
  previously_not_installed_rpm_fusion=false
fi
}

UNINSTALL_RPM_FUSION() {
if "${previously_not_installed_rpm_fusion}"; then
  if command -v dnf5 &> /dev/null; then
    dnf5 -y remove rpmfusion-free-release rpmfusion-nonfree-release
  elif command -v rpm-ostree &> /dev/null; then
    rpm-ostree uninstall rpmfusion-free-release rpmfusion-nonfree-release
  fi
fi
}

INSTALL_NVIDIA_DRIVER() {
BASE_IMAGE_NAME=${BASE_IMAGE##*/}
BASE_IMAGE_NAME=${BASE_IMAGE_NAME%-*}

# Fetch Common AKMODS & Kernel RPMS
skopeo copy --retry-times 3 docker://ghcr.io/ublue-os/akmods@sha256:42c7592e3a3bad44d3792f63e521faf39951a77ae48fccea64b6bcb9f928ba87 dir:/tmp/akmods
AKMODS_TARGZ=$(jq -r '.layers[].digest' </tmp/akmods/manifest.json | cut -d : -f 2)
tar -xvzf /tmp/akmods/"$AKMODS_TARGZ" -C /tmp/
mv /tmp/rpms/* /tmp/akmods/

echo "Pulling akmods nvidia image"
skopeo copy --retry-times 3 docker://ghcr.io/ublue-os/akmods-nvidia-open@sha256:5ee11a297bd272e192cd452e362af721181a140d2e403d480ff5e0c26b90b6d9 dir:/tmp/akmods-rpms

NVIDIA_TARGZ=$(jq -r '.layers[].digest' </tmp/akmods-rpms/manifest.json | cut -d : -f 2)
tar -xvzf /tmp/akmods-rpms/"$NVIDIA_TARGZ" -C /tmp/
mv /tmp/rpms/* /tmp/akmods-rpms/

# Install Nvidia RPMs
IMAGE_NAME="${BASE_IMAGE_NAME}" RPMFUSION_MIRROR="" /tmp/akmods-rpms/ublue-os/nvidia-install.sh
validate_installed_modules
rm -f /usr/share/vulkan/icd.d/nouveau_icd.*.json
ln -sf libnvidia-ml.so.1 /usr/lib64/libnvidia-ml.so

KARGS_D="/usr/lib/bootc/kargs.d"
BLUEBUILD_NVIDIA_TOML="${KARGS_D}/00-bluebuild-nvidia-kargs.toml"

# Create kargs folder if doesn't exist
mkdir -p "${KARGS_D}"
echo 'kargs = ["rd.driver.blacklist=nouveau", "modprobe.blacklist=nouveau", "nvidia-drm.modeset=1", "initcall_blacklist=simpledrm_platform_driver_init"]' >> "${BLUEBUILD_NVIDIA_TOML}"
}

INSTALL=()
INSTALL_NVIDIA=false
NVIDIA_DRIVER=""
get_json_array INSTALL 'try .["install"][]' "$1"

KERNEL_BASE=$(echo "$1" | jq -r 'try .["base"]')
if [[ -z $KERNEL_BASE || $KERNEL_BASE == "null" ]]; then
	KERNEL_BASE="main"
fi

NVIDIA_DRIVER=$(echo "$1" | jq -r 'try .["nvidia-driver"]')
if [[ $NVIDIA_DRIVER == "nvidia" || $NVIDIA_DRIVER == "nvidia-open" ]]; then
    INSTALL_NVIDIA=true

    if [[ "$NVIDIA_DRIVER" == *"open"* ]]; then
        echo "nvidia-open kernel driver selected"
    else
        echo "nvidia-lts kernel driver selected"
        curl -fLsS --retry 5 -o /etc/yum.repos.d/fedora-nvidia-580.repo https://negativo17.org/repos/fedora-nvidia-580.repo
        sed -i '/^enabled=1/a\priority=90' /etc/yum.repos.d/fedora-nvidia-580.repo
        NVIDIA_DRIVER="nvidia-lts"
    fi
fi


if [[ ${#INSTALL[@]} -lt 1 && $INSTALL_NVIDIA == false ]]; then
  echo "ERROR: You didn't specify any akmod or nvidia driver for installation!"
  exit 1
fi

INSTALL_PATH=("${INSTALL[@]/#/\/tmp/rpms/kmods/*}")
INSTALL_PATH=("${INSTALL_PATH[@]/%/*.rpm}")
INSTALL_STR=$(echo "${INSTALL_PATH[*]}" | tr -d '\n')

# Universal Blue switched from RPMFusion to negativo17 repos
# WL & V4L2Loopback akmods currently require RPMFusion repo, so we temporarily install then uninstall it

echo "Installing akmods"

echo "Total length of modules to install: ${#INSTALL[@]}"
if [[ ${#INSTALL[@]} -gt 0 ]]; then
    echo "Installing: $(echo "${INSTALL[*]}" | tr -d '\n')"
    ENABLE_AKMODS_REPO
    INSTALL_RPM_FUSION
    # shellcheck disable=SC2086
    rpm-ostree install ${INSTALL_STR}
    UNINSTALL_RPM_FUSION
fi

if [[ $INSTALL_NVIDIA == true ]]; then
    echo "Installing nvidia driver: $NVIDIA_DRIVER"
    INSTALL_NVIDIA_DRIVER
fi
