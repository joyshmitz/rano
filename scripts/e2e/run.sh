#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <test-name> <test-script> [args...]" >&2
  exit 1
fi

TEST_NAME="$1"
shift
TEST_SCRIPT="$1"
shift

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

export E2E_TEST_NAME="${TEST_NAME}"
export E2E_ARGS="$*"
export E2E_LOG_DIR="${E2E_LOG_DIR:-logs/e2e}"

mkdir -p "${E2E_LOG_DIR}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
export E2E_LOG="${E2E_LOG_DIR}/${TEST_NAME}-${TS}.log"

exec > >(tee -a "${E2E_LOG}") 2>&1

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

e2e_init
e2e_header

if ( set -euo pipefail; source "${TEST_SCRIPT}" ); then
  e2e_pass
else
  e2e_fail "test script exited non-zero"
fi
