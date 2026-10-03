#!/bin/bash
set -euo pipefail
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version=$(bash "$PROJECT_DIR/bin/egress" --version | awk '{print $2}')
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '无效版本' >&2; exit 1; }
output=${1:-$PROJECT_DIR/dist}
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd)
stage=$(mktemp -d /tmp/oneegress-build.XXXXXX)
cleanup() {
  # Only our known generated files; never recurse over a caller-supplied path.
  rm -f -- "$stage/oneegress-$version/bin/egress" "$stage/oneegress-$version/install.sh" \
    "$stage/oneegress-$version/config.example.json" "$stage/oneegress-$version/README.md" "$stage/oneegress-$version/CHANGELOG.md"
  rmdir "$stage/oneegress-$version/bin" "$stage/oneegress-$version" "$stage"
}
trap cleanup EXIT
install -d "$stage/oneegress-$version/bin"
install -m 755 "$PROJECT_DIR/bin/egress" "$stage/oneegress-$version/bin/egress"
install -m 755 "$PROJECT_DIR/install.sh" "$stage/oneegress-$version/install.sh"
for file in config.example.json README.md CHANGELOG.md; do
  install -m 644 "$PROJECT_DIR/$file" "$stage/oneegress-$version/$file"
done
archive="oneegress-v$version.tar.gz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -I 'gzip -n' \
  -cf "$output/$archive" -C "$stage" "oneegress-$version"
(cd -- "$output" && sha256sum "$archive" > SHA256SUMS)
printf '发布包: %s\n校验文件: %s\n' "$output/$archive" "$output/SHA256SUMS"
