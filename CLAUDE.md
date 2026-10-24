# segfault.me

Hugo static blog.

## Procedures
- `hugo` is not installed locally. Build in a container pinned to Hugo 0.113.0: `docker run --rm -it --user "$(id -u):$(id -g)" -v$(pwd):/src hugomods/hugo:exts-0.113.0 hugo`.
- New posts: use the theme's post archetype. It sets `draft: true`; remove it to publish.

## Deployment (cortex.segfault.me)
- The host is deployed only by `build/setup.sh` as root (layout in `build/README.md`). Never start containers or edit files under `/app/segfault.me` by hand: change the repo, merge to `main`, re-run the script on the host.
- `build/.env` (the segv cluster's public address) and `build/certs/` are host-local and git-ignored.
- `/auth/` is proxied nginx to nghttpx to the segv cluster's Gateway (Keycloak). The backend certificate is verified through the `origin.segfault.me` alias; do not reintroduce `insecure=yes`.

## Traps
- Permalinks are derived from `date` and the filename/slug. Changing either breaks published URLs.
- `*.png` and `*.jpg` are Git LFS. Ensure LFS is set up before adding images.
- TLS is a Cloudflare Origin CA cert, so the site only works behind the Cloudflare proxy. Certs and keys are git-ignored; `build/setup.sh` issues a new one via the Cloudflare API when none exists (needs `CLOUDFLARE_API_TOKEN`). Private keys cannot be re-downloaded from Cloudflare.
- Never read or copy private keys from the production host (`core@cortex.segfault.me`).
- The theme uses `resources.ToCSS`, removed in Hugo 0.128: do not move to an unpinned or newer Hugo image without porting the theme to `css.Sass`.
- `static/keybase.txt` is an identity proof; leave it alone.

## Conventions
- Posts with assets are page bundles (`<slug>/index.md`); otherwise `<slug>.md`.
- Reuse existing tags; check current posts before adding new ones.
