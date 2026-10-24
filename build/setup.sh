#!/usr/bin/env bash
# Deploys on a Debian-based host: installs dependencies, clones the
# repository, generates the site with Hugo and starts it with docker-compose.
# Must be run as root. Safe to re-run to update the deployment.
# Preconditions, each only needed the first time:
#   CLOUDFLARE_API_TOKEN  a token with the `Zone > SSL and Certificates > Edit permission`, used when build/certs has
#                         no certificate.
#   SEGV_ORIGIN_IP        public address of the segv cluster, written to build/.env when that file does not exist.
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

CERTS=$DEST/build/certs
mkdir -p "$CERTS"
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

if [ ! -f "$DEST/build/.env" ]; then
  : "${SEGV_ORIGIN_IP:?required to create build/.env}"
  echo "SEGV_ORIGIN_IP=$SEGV_ORIGIN_IP" > "$DEST/build/.env"
fi

if ! cmp -s "$DEST/build/sslh/sslh" /etc/default/sslh; then
  install -m 644 "$DEST/build/sslh/sslh" /etc/default/sslh
  systemctl enable sslh
  systemctl restart sslh
fi

# The theme uses resources.ToCSS, removed in Hugo 0.128; 0.113.0 is the version the live site was built with.
docker run --rm --user "$(id -u):$(id -g)" -v "$DEST":/src \
  hugomods/hugo:exts-0.113.0 hugo

cd "$DEST/build"
docker-compose up -d --remove-orphans
# Mounted configuration is not noticed by `up`.
docker-compose exec -T nginx nginx -t
docker-compose exec -T nginx nginx -s reload
docker-compose kill -s HUP nghttpx
