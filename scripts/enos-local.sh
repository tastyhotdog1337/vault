#!/usr/bin/env bash

# The enos-local-builder is used by Enos for artifact_source:local scenario variants.

set -euo pipefail

# Get the full version information
# this is only needed for local enos builds in order to get the default version from version_base.go
# this should match the default version that the binary has been built with
# CRT release builds use the new static version from ./release/VERSION
function version() {
  local version
  local prerelease
  local metadata

  version=$(version_base)
  prerelease=$(version_pre)
  metadata=$(version_metadata)

  if [ -n "$metadata" ] && [ -n "$prerelease" ]; then
    echo "$version-$prerelease+$metadata"
  elif [ -n "$metadata" ]; then
    echo "$version+$metadata"
  elif [ -n "$prerelease" ]; then
    echo "$version-$prerelease"
  else
    echo "$version"
  fi
}

# Get the base version
function version_base() {
  : "${VAULT_VERSION:=""}"

  if [ -n "$VAULT_VERSION" ]; then
    echo "$VAULT_VERSION"
    return
  fi

  : "${VERSION_FILE:=$(repo_root)/version/version_base.go}"
  awk '$1 == "Version" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "$VERSION_FILE"
}

# Get the version pre-release
function version_pre() {
  : "${VAULT_PRERELEASE:=""}"

  if [ -n "$VAULT_PRERELEASE" ]; then
    echo "$VAULT_PRERELEASE"
    return
  fi

  : "${VERSION_FILE:=$(repo_root)/version/version_base.go}"
  awk '$1 == "VersionPrerelease" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "$VERSION_FILE"
}

# Get the version metadata, which is commonly the edition
function version_metadata() {
  : "${VAULT_METADATA:=""}"

  if [ -n "$VAULT_METADATA" ]; then
    echo "$VAULT_METADATA"
    return
  fi

  : "${VERSION_FILE:=$(repo_root)/version/version_base.go}"
  awk '$1 == "VersionMetadata" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "$VERSION_FILE"
}

# Determine the root directory of the repository
function repo_root() {
  git rev-parse --show-toplevel
}

# Bundle the dist directory
# this is done by the actions-go-build action so only needed for enos local builds
function bundle() {
  : "${BUNDLE_PATH:=$(repo_root)/vault.zip}"
  echo "--> Bundling dist/* to $BUNDLE_PATH"
  zip -r -j "$BUNDLE_PATH" dist/
}

# Run Enos local
function main() {
  case $1 in
  bundle)
    bundle
  ;;
  version)
    version
  ;;
  version-base)
    version_base
  ;;
  version-pre)
    version_pre
  ;;
  version-meta)
    version_metadata
  ;;
  *)
    echo "unknown sub-command" >&2
    exit 1
  ;;
  esac
}

main "$@"