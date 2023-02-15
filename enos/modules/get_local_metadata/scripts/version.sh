#!/bin/env bash
set -eu -o pipefail

pushd "$(git rev-parse --show-toplevel)" > /dev/null
CWD="$(pwd)"
$CWD/get-local-version.sh version
popd > /dev/null
