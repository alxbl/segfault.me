#!/usr/bin/env bash
# Deploys on a Debian-based host: installs dependencies, clones the
# repository, generates the site with Hugo and starts it with docker-compose.
# Must be run as root. Safe to re-run to update the deployment.
# Precondition: CLOUDFLARE_API_TOKEN is set to a token with the `Zone > SSL and Certificates > Edit permission`
#               (it is only used when no certificate exists yet.)
set -euo pipefail

REPO=https://github.com/alxbl/segfault.me.git
DEST=/app/segfault.me

apt-get update
apt-get install -y docker.io docker-compose sslh git git-lfs curl jq openssl

if [ -d "$DEST/.git" ]; then
  git -C "$DEST" pull --ff-only
else
  git clone "$REPO" "$DEST"
fi
git -C "$DEST" lfs pull

CERTS=$DEST/build/nginx/conf.d
if [ ! -f "$CERTS/segfault.me.pem" ]; then
  : "${CLOUDFLARE_API_TOKEN:?required to issue the origin certificate}"
  (umask 077
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=segfault.me" -keyout "$CERTS/segfault.me.key" -out /tmp/segfault.me.csr
  jq -n --rawfile csr /tmp/segfault.me.csr \
    '{csr: $csr, hostnames: ["segfault.me", "*.segfault.me"],
      request_type: "origin-ecc", requested_validity: 5475}' |
    curl -fsS https://api.cloudflare.com/client/v4/certificates \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      -H "Content-Type: application/json" --data @- |
    jq -er '.result.certificate' > "$CERTS/segfault.me.pem"
  rm /tmp/segfault.me.csr)
fi

docker run --rm --user "$(id -u):$(id -g)" -v "$DEST":/src \
  hugomods/hugo:debian-ci-non-root hugo

cd "$DEST/build"
docker-compose up -d
