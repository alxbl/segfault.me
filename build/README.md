# Deployment (cortex.segfault.me)

`setup.sh` is the whole deployment: run it as root on the host, it is safe to re-run to update.

```
Cloudflare -> sslh :443 -> nginx 127.0.0.1:4443 -> static site
                                             `-> /auth/ -> nghttpx -> segv cluster Gateway -> Keycloak
```

- Everything lives under `/app/segfault.me`; nothing else on the host is configuration.
- First run needs `CLOUDFLARE_API_TOKEN` (origin certificate, kept in `build/certs/`, never committed) and
  `SEGV_ORIGIN_IP`, the cluster's public address (stored in `build/.env`, never committed). If the address changes, edit
  `build/.env` and run `docker-compose up -d` in `build/`.
- `build/sslh/sslh` becomes `/etc/default/sslh`.
- nghttpx reaches the cluster as `origin.segfault.me`, an alias injected with `extra_hosts` that matches the Gateway's
  `*.segfault.me` certificate, so the backend certificate stays verified.
