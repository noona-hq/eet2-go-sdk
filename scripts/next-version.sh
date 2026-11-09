#!/usr/bin/env bash

set -euo pipefail

BUMP="${BUMP:-auto}"
FORCE="${FORCE:-false}"
INITIAL_VERSION="v0.1.0"
RELEASE_PATHS=(':(glob)**/*.go' 'go.mod' 'go.sum')
BREAKING_SUBJECT='^[a-z]+(\([a-z0-9-]+\))?!:'
FEATURE_SUBJECT='^feat(\([a-z0-9-]+\))?:'
BREAKING_FOOTER='^BREAKING[ -]CHANGE:'

last=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)

if [[ -z "${last}" ]]; then
  echo "Releasing ${INITIAL_VERSION}"
  echo "version=${INITIAL_VERSION}" >> "${GITHUB_OUTPUT}"
  exit 0
fi

if [[ "${FORCE}" != "true" ]] && git diff --quiet "${last}" HEAD -- "${RELEASE_PATHS[@]}"; then
  echo "No Go changes since ${last}, skipping release"
  echo "version=" >> "${GITHUB_OUTPUT}"
  exit 0
fi

if [[ "${BUMP}" == "auto" ]]; then
  BUMP="patch"
  if git log --format=%s "${last}..HEAD" | grep -qE "${FEATURE_SUBJECT}"; then
    BUMP="minor"
  fi
  if git log --format=%s "${last}..HEAD" | grep -qE "${BREAKING_SUBJECT}" || git log --format=%b "${last}..HEAD" | grep -qE "${BREAKING_FOOTER}"; then
    BUMP="major"
  fi
  if [[ "${BUMP}" == "major" && "${last}" == v0.* ]]; then
    BUMP="minor"
  fi
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

echo "Releasing ${next} (${BUMP})"
echo "version=${next}" >> "${GITHUB_OUTPUT}"
