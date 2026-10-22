# segfault.me

Hugo static blog.

## Procedures
- `hugo` is not installed locally. Build in a container: `docker run --rm -it -v$(pwd):/src hugomods/hugo:debian-ci-non-root`.
- New posts: use the theme's post archetype. It sets `draft: true`; remove it to publish.

## Traps
- Permalinks are derived from `date` and the filename/slug. Changing either breaks published URLs.
- `*.png` and `*.jpg` are Git LFS. Ensure LFS is set up before adding images.
- TLS is a Cloudflare Origin CA cert, so the site only works behind the Cloudflare proxy. Certs and keys are git-ignored; `build/setup.sh` issues a new one via the Cloudflare API when none exists (needs `CLOUDFLARE_API_TOKEN`). Private keys cannot be re-downloaded from Cloudflare.
- Never read or copy private keys from the production host (`core@cortex.segfault.me`).
- `static/keybase.txt` is an identity proof; leave it alone.

## Conventions
- Posts with assets are page bundles (`<slug>/index.md`); otherwise `<slug>.md`.
- Reuse existing tags; check current posts before adding new ones.
