#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy-release.sh must run as root" >&2
  exit 1
fi

ref=${1:?"usage: deploy-release.sh <git-ref>"}
repo_url=${MERGER_REPO_URL:-https://github.com/ssharkkky/singbox-merger.git}
deploy_root=${MERGER_DEPLOY_ROOT:-/opt/singbox-merger-deploy}
service=${MERGER_SERVICE:-singbox-merger.service}
run_user=${MERGER_RUN_USER:-singbox-merger}
skip_restart=${MERGER_SKIP_RESTART:-0}

if [[ "$ref" == -* || ! "$ref" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "invalid git ref" >&2
  exit 1
fi

install -d -o root -g root -m 0755 "$deploy_root" "$deploy_root/releases"
stage=$(mktemp -d "$deploy_root/.staging.XXXXXXXX")

git -C "$stage" init --quiet
git -C "$stage" remote add origin "$repo_url"
GIT_TERMINAL_PROMPT=0 git -C "$stage" fetch --quiet --depth=1 origin "$ref"
git -C "$stage" checkout --quiet --detach FETCH_HEAD
sha=$(git -C "$stage" rev-parse HEAD)
release="$deploy_root/releases/$sha"

if [[ -e "$release" ]]; then
  echo "release already exists: $release" >&2
  exit 1
fi

mv "$stage" "$release"
chmod 0755 "$release"
python3 -m venv "$release/.venv"
"$release/.venv/bin/python" -m pip install \
  --disable-pip-version-check --no-deps -r "$release/requirements.lock"
"$release/.venv/bin/python" -m pip check
runuser -u "$run_user" -- env PYTHONDONTWRITEBYTECODE=1 \
  "$release/.venv/bin/python" -m unittest discover \
  -s "$release/tests" -t "$release" -v

previous=""
if [[ -L "$deploy_root/current" ]]; then
  previous=$(readlink -f "$deploy_root/current")
fi

next_link="$deploy_root/.current.$$.next"
ln -s "releases/$sha" "$next_link"
mv -Tf "$next_link" "$deploy_root/current"

if [[ "$skip_restart" == 1 ]]; then
  echo "prepared $sha (service restart skipped)"
  exit 0
fi

if ! systemctl restart "$service"; then
  if [[ -n "$previous" ]]; then
    rollback_link="$deploy_root/.current.$$.rollback"
    ln -s "$previous" "$rollback_link"
    mv -Tf "$rollback_link" "$deploy_root/current"
    systemctl restart "$service"
  fi
  exit 1
fi

healthy=no
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 3 http://127.0.0.1:25600/api/templates >/dev/null; then
    healthy=yes
    break
  fi
  sleep 1
done

if [[ "$healthy" != yes ]]; then
  if [[ -n "$previous" ]]; then
    rollback_link="$deploy_root/.current.$$.rollback"
    ln -s "$previous" "$rollback_link"
    mv -Tf "$rollback_link" "$deploy_root/current"
    systemctl restart "$service"
  fi
  echo "health check failed; previous release restored" >&2
  exit 1
fi

echo "deployed $sha"
