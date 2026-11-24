# dfcheck

A small, dependency free Dockerfile checker for production habits. It does not try to replace a full linter; it flags the handful of mistakes that most often make images bigger, slower to stop or less safe on a real server.

## Install

```bash
cargo install dfcheck
```

## Usage

```bash
dfcheck                       # checks ./Dockerfile
dfcheck api/Dockerfile worker/Dockerfile
dfcheck --ignore DF006 --no-info Dockerfile
```

Output uses `file:line: CODE severity: message`, so editors and CI logs can link to the line. Exit code `1` when any warning is found, `2` for bad arguments or unreadable files, `0` otherwise, which makes it easy to use as a CI step before `docker build`.

## Rules

- DF001: base image has no tag or uses `latest`
- DF002: final stage runs as root (no `USER`, or `USER root`)
- DF003: `apt-get install` without `--no-install-recommends`
- DF004: apt lists not removed in the same `RUN`
- DF005: `ADD` used for local files or remote URLs instead of `COPY` or a verified download
- DF006 (info): no `HEALTHCHECK` in the file
- DF007: something that looks like a secret set in `ENV` or an `ARG` default
- DF008: `CMD` or `ENTRYPOINT` in shell form, so the app may never receive SIGTERM
- DF009: `apk add` without `--no-cache`
- DF010: `sudo` inside a build step

Continuation lines are joined and findings point at the line where the instruction starts. In multi stage builds, references to earlier stages are not treated as untagged images, and the `USER` check applies to the final stage only.

## Why these rules

Each rule maps to a habit that matters once containers run in production on your own server. The reasoning is laid out in [Docker security best practices for production](https://peon.sh/blogs/docker-security-best-practices-production). After the build, scan the image itself for known vulnerabilities as described in the [Trivy image scanning guide](https://peon.sh/blogs/docker-image-scanning-trivy), and keep images small with the tips in [reducing Docker image size](https://peon.sh/blogs/reduce-docker-image-size).

Built by the team behind [Peon](https://peon.sh/), an open-source self-hosted deployment platform for Docker apps.

## License

MIT
