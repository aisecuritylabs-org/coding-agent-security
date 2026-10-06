# GitHub Copilot security audit: minimal, offline, read-only.
#
# Base:     official Alpine Linux image, pinned by digest (3.24.2).
# Packages: bash and jq, pinned, from Alpine's official repository.
# VS Code settings are JSON with comments; common/jsonc.awk converts them.
# Nothing else is downloaded; the audit itself runs with no network.
#
# Build (from the repository root):
#   docker build -f copilot/audit/Dockerfile -t copilot-audit .

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

LABEL org.opencontainers.image.title="copilot-audit" \
      org.opencontainers.image.description="Read-only, offline audit of a GitHub Copilot setup against the AISecurityLabs.org hardening guide" \
      org.opencontainers.image.vendor="AISecurityLabs.org" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/aisecuritylabs-org/coding-agent-security"

RUN apk add --no-cache bash=5.3.9-r1 jq=1.8.2-r0

# Only the audit, the shared library and the framework mappings are copied in.
COPY common/audit-lib.sh          /opt/audit/audit-lib.sh
COPY common/jsonc.awk             /opt/audit/jsonc.awk
COPY common/gitignore.sh          /opt/audit/gitignore.sh
COPY copilot/audit/audit.sh       /opt/audit/audit.sh
COPY copilot/audit/mappings.json  /opt/audit/mappings.json
RUN chmod 0555 /opt/audit/audit.sh \
 && chmod 0444 /opt/audit/audit-lib.sh /opt/audit/jsonc.awk /opt/audit/gitignore.sh /opt/audit/mappings.json

# Unprivileged by default; run.sh / run.ps1 pass your own uid:gid so the
# container can read your read-only mounts.
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/opt/audit/audit.sh"]
