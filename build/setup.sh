# TODO: rootless container.

# Must be run as root.
apt update && sudo apt install -y \
  docker \
  docker-compose \
  sslh \
  git


# Generate contents
# docker run --rm -it -v$(pwd):/src hugomods/hugo:debian-ci-non-root

mkdir -p /app/segv

cp -r nginx /app/nginx
cp -r nghttpx /app/nghttpx
_pwd=$(pwd)
pushd /

# ... to be completed
