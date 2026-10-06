# Claude Code security audit: minimal, offline, read-only.
#
# Base:     official Alpine Linux image, pinned by digest (3.24.2).
# Packages: bash and jq only, pinned, from Alpine's official main repository.
# Nothing else is downloaded; the audit itself runs with no network.
#
# Build (from the repository root):
#   docker build -f claude-code/audit/Dockerfile -t claude-code-audit .

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

LABEL org.opencontainers.image.title="claude-code-audit" \
      org.opencontainers.image.description="Read-only, offline audit of a Claude Code setup against the AISecurityLabs.org hardening guide" \
      org.opencontainers.image.vendor="AISecurityLabs.org" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/aisecuritylabs-org/coding-agent-security"

RUN apk add --no-cache bash=5.3.9-r1 jq=1.8.2-r0

# Only the audit script, its framework mappings and the hook test suite are copied in.
COPY claude-code/audit/audit.sh      /opt/audit/audit.sh
COPY claude-code/audit/mappings.json /opt/audit/mappings.json
COPY common/gitignore.sh          /opt/audit/gitignore.sh
COPY claude-code/tests/test-hooks.sh /opt/audit/tests/test-hooks.sh
RUN chmod 0555 /opt/audit/audit.sh /opt/audit/tests/test-hooks.sh \
 && chmod 0444 /opt/audit/mappings.json /opt/audit/gitignore.sh

# Unprivileged by default; run.sh / run.ps1 pass your own uid:gid so the
# container can read your read-only mounts.
USER 65534:65534
WORKDIR /tmp

ENTRYPOINT ["/opt/audit/audit.sh"]
