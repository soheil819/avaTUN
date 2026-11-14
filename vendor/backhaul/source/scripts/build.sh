#!/bin/sh
# Offline independent Go build by ir_spoof - https://t.me/ir_spoof
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
command -v go >/dev/null 2>&1 || {
    printf '%s\n' 'Install Go 1.26+ before this offline build.' >&2
    exit 1
}
[ -f "$project_dir/vendor/modules.txt" ] || {
    printf '%s\n' 'The complete vendored source bundle is required for an offline build.' >&2
    exit 1
}
export CGO_ENABLED=0 GOTOOLCHAIN=local GOTELEMETRY=off GOPROXY=off GOSUMDB=off
export GOOS=linux
GOARCH=${GOARCH:-amd64}
export GOARCH
case "$GOARCH" in amd64|arm64) ;; *) printf '%s\n' 'Choose GOARCH=amd64 or GOARCH=arm64.' >&2; exit 1 ;; esac
mkdir -p "$project_dir/build"
go -C "$project_dir" build -mod=vendor -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid=' -o build/backhaul ./cmd/backhaul
printf '%s\n' 'Built build/backhaul for Linux. Attribution: t.me/ir_spoof'
