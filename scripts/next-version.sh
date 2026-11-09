#!/usr/bin/env bash

set -euo pipefail

BUMP="${BUMP:-patch}"
FORCE="${FORCE:-false}"
INITIAL_VERSION="v0.1.0"
RELEASE_PATHS=(':(glob)**/*.go' 'go.mod' 'go.sum')

last=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)

if [[ -z "${last}" ]]; then
  next="${INITIAL_VERSION}"
else
  if [[ "${FORCE}" != "true" ]] && git diff --quiet "${last}" HEAD -- "${RELEASE_PATHS[@]}"; then
    echo "No Go changes since ${last}, skipping release"
    echo "version=" >> "${GITHUB_OUTPUT}"
    exit 0
  fi
  IFS=. read -r major minor patch <<< "${last#v}"
  case "${BUMP}" in
    major) next="v$((major + 1)).0.0" ;;
    minor) next="v${major}.$((minor + 1)).0" ;;
    patch) next="v${major}.${minor}.$((patch + 1))" ;;
    *)
      echo "Unknown bump ${BUMP}" >&2
      exit 1
      ;;
  esac
fi

echo "Releasing ${next}"
echo "version=${next}" >> "${GITHUB_OUTPUT}"
