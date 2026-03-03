#!/bin/sh
# Download and install sharness test framework
# Usage: bash tests/install-sharness.sh

SHARNESS_VERSION="1.2.0"
SHARNESS_URL="https://github.com/felipec/sharness/archive/refs/tags/v${SHARNESS_VERSION}.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHARNESS_DIR="${SCRIPT_DIR}/sharness"

if test -f "${SHARNESS_DIR}/sharness.sh"; then
    echo "Sharness already installed at ${SHARNESS_DIR}/sharness.sh"
    exit 0
fi

echo "Installing sharness v${SHARNESS_VERSION}..."
mkdir -p "${SHARNESS_DIR}"

curl -sL "${SHARNESS_URL}" | tar xz --strip-components=1 -C "${SHARNESS_DIR}" || {
    echo "Failed to download sharness. Check your internet connection."
    exit 1
}

if test -f "${SHARNESS_DIR}/sharness.sh"; then
    echo "Sharness v${SHARNESS_VERSION} installed successfully."
else
    echo "Installation failed: sharness.sh not found."
    exit 1
fi
