# OpenAI Codex security audit: minimal, offline, read-only.
#
# Base:     official Alpine Linux image, pinned by digest (3.24.2).
# Packages: bash, jq and yq (to read Codex's TOML config), pinned, from
#           Alpine's official repositories.
# Nothing else is downloaded; the audit itself runs with no network.
#
# Build (from the repository root):
#   docker build -f codex/audit/Dockerfile -t codex-audit .

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

LABEL org.opencontainers.image.title="codex-audit" \
      org.opencontainers.image.description="Read-only, offline audit of an OpenAI Codex setup against the AISecurityLabs.org hardening guide" \
      org.opencontainers.image.vendor="AISecurityLabs.org" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/aisecuritylabs-org/coding-agent-security"

RUN apk add --no-cache bash=5.3.9-r1 jq=1.8.2-r0 yq-go=4.53.3-r1

# Only the audit script and its framework mappings are copied in.
COPY codex/audit/audit.sh      /opt/audit/audit.sh
COPY codex/audit/mappings.json /opt/audit/mappings.json
COPY common/gitignore.sh          /opt/audit/gitignore.sh
RUN chmod 0555 /opt/audit/audit.sh \
 && chmod 0444 /opt/audit/mappings.json /opt/audit/gitignore.sh

# Unprivileged by default; run.sh / run.ps1 pass your own uid:gid so the
# container can read your read-only mounts.
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/opt/audit/audit.sh"]
